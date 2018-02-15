/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <sys/types.h>
#include <regex.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "nest.h"

static void pack_string(msgpack_packer *packer, const char *str) {
	if(str == NULL) {
		msgpack_pack_nil(packer);
	} else {
		int len = (int) strlen(str);
		msgpack_pack_str(packer, len);
		msgpack_pack_str_body(packer, str, len);
	}
}

static int configure(struct filter_nest_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    char *tmp;

    ctx->nesting_key = NULL;
    ctx->wildcard = NULL;

    /* Nest key name */
    tmp = flb_filter_get_property("Nest_under", f_ins);
    if (tmp) {
        ctx->nesting_key = flb_strdup(tmp);
        ctx->nesting_key_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] Key \"Nest_under\" is missing\n");
        return -1;
    }

    /* Wildcard key name */
    tmp = flb_filter_get_property("Wildcard", f_ins);
    if (tmp) {
        ctx->wildcard = flb_strdup(tmp);
        ctx->wildcard_len = strlen(tmp);

        if (ctx->wildcard[ctx->wildcard_len - 1] == '*') {
          ctx->wildcard_is_dynamic = FLB_TRUE;
          ctx->wildcard_len--;
        } else {
          ctx->wildcard_is_dynamic = FLB_FALSE;
        }

    } else {
        flb_error("[filter_parser] Key \"Wildcard\" is missing\n");
        return -1;
    }

    return 0;
}

static inline void map_pack_each_if(
    msgpack_packer *packer,
    msgpack_object *map,
    struct filter_nest_ctx *ctx,
    bool (*f)(msgpack_object_kv *kv, struct filter_nest_ctx *ctx)
    )
{
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f)(&map->via.map.ptr[i], ctx)) {
          msgpack_pack_object(packer, map->via.map.ptr[i].key);
          msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline int map_count(
    msgpack_object *map,
    struct filter_nest_ctx *ctx,
    bool (*f)(msgpack_object_kv *kv, struct filter_nest_ctx *ctx)
    )
{
  int i;
  int count = 0;

  for (i = 0; i < map->via.map.size; i++) {
    if ((*f)(&map->via.map.ptr[i], ctx)) {
      count++;
    }
  }
  return count;
}

static inline bool is_kv_to_nest(
    msgpack_object_kv *kv,
    struct filter_nest_ctx *ctx
    ) 
{

  msgpack_object *obj;
  char *key;
  int klen;

  obj = &kv->key;

  if (obj->type == MSGPACK_OBJECT_BIN) {
    key = (char *) obj->via.bin.ptr;
    klen = obj->via.bin.size;
  } else if (obj->type == MSGPACK_OBJECT_STR) {
    key  = (char *) obj->via.str.ptr;
    klen = obj->via.str.size;
  } else {
    return false;
  }

  if (ctx->wildcard_is_dynamic) {
    // this will positively match "ABC123" with wildcard "ABC*" 
    return (strncmp(key, ctx->wildcard, ctx->wildcard_len) == 0);
  } else {
    // this will positively match "ABC" with wildcard "ABC" 
    return (
        (ctx->wildcard_len == klen) &&
        (strncmp(key, ctx->wildcard, ctx->wildcard_len) == 0)
        );
  }

}

static inline bool is_not_kv_to_nest(
    msgpack_object_kv *kv,
    struct filter_nest_ctx *ctx
    ) 
{
  return !is_kv_to_nest(kv, ctx);
}

static inline void apply_nesting_rules(
    msgpack_packer *packer,
    msgpack_object *root,
    struct filter_nest_ctx *ctx)
{
    msgpack_object ts  = root->via.array.ptr[0];
    msgpack_object map  = root->via.array.ptr[1];

    msgpack_pack_object(packer, ts);

    size_t items_to_nest_count = map_count(&map, ctx, &is_kv_to_nest);
    size_t items_toplevel_count = (map.via.map.size - items_to_nest_count + 1);

    // Create a new map with toplevel items +1 for nested map
    msgpack_pack_map(packer, items_toplevel_count);
    map_pack_each_if(packer, &map, ctx, is_not_kv_to_nest);

    // Pack the nested map key
    pack_string(packer, ctx->nesting_key);
    // Create the nest map value
    msgpack_pack_map(packer, items_to_nest_count);
    // Add the nested items
    map_pack_each_if(packer, &map, ctx, is_kv_to_nest);
}

static int cb_nest_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    struct filter_nest_ctx *ctx;

    // Create context
    ctx = flb_malloc(sizeof(struct filter_nest_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    if ( configure(ctx, f_ins, config) < 0 ){
        flb_free(ctx);
        return -1;
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_nest_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *f_ins,
                          void *context,
                          struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    struct filter_nest_ctx *ctx = context;

    msgpack_sbuffer sbuffer;
    msgpack_sbuffer_init(&sbuffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &sbuffer, msgpack_sbuffer_write);

    flb_debug("[filter_nest] Operating nest filter. Moving keys matching '%s' to '%s'", 
        ctx->wildcard,
        ctx->nesting_key
        );

    // Records come in the format,
    //
    // [ TIMESTAMP, { K1:V1, K2:V2 ...} ], 
    // [ TIMESTAMP, { K1:V1, K2:V2 ...} ]
    // ex,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
          flb_debug("[filter_nest] Record is an array");
          msgpack_object_print(stdout, result.data);

          apply_nesting_rules(&packer, &result.data, ctx);
          // msgpack_pack_object(&packer, result.data);

        } else {
          flb_debug("[filter_nest] Record is NOT an array, skipping");
          msgpack_pack_object(&packer, result.data);
          continue;
        }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf   = sbuffer.data;
    *out_size = sbuffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_nest_exit(void *data, struct flb_config *config)
{
    struct filter_nest_ctx *ctx = data;

    flb_free(ctx->nesting_key);
    flb_free(ctx->wildcard);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_nest_plugin = {
    .name         = "nest",
    .description  = "nest events by specified field values",
    .cb_init      = cb_nest_init,
    .cb_filter    = cb_nest_filter,
    .cb_exit      = cb_nest_exit,
    .flags        = 0
};
