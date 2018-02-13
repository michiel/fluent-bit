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

static inline void nest_data(
    msgpack_packer *packer,
    msgpack_object map,
    struct filter_nest_ctx *ctx)
{

    int i;
    int klen;
    int vlen;
    char *key;
    char *val;
    msgpack_object *k;
    msgpack_object *v;
    struct mk_list *head;

    size_t keys_to_nest = 0;
    size_t keys_to_keep = 0;
    bool matched = false;

    msgpack_packer nest_packer;
    msgpack_sbuffer* nest_buffer = msgpack_sbuffer_new();
    msgpack_packer_init(&nest_packer, &nest_buffer, msgpack_sbuffer_write);

    // Do an inventory of the map
    for (i = 0; i < map.via.map.size; i++) {
        k = &map.via.map.ptr[i].key;

        if (k->type == MSGPACK_OBJECT_BIN) {
            key = (char *) k->via.bin.ptr;
            klen = k->via.bin.size;
        } else if (k->type == MSGPACK_OBJECT_STR) {
            key  = (char *) k->via.str.ptr;
            klen = k->via.str.size;
        } else {
            continue;
        }

        flb_debug("XX nest_data : inventory iteration %d - key is %s\n", i, key);

        if (strncmp(key, ctx->nesting_key, klen) == 0) {
            flb_debug("[filter_nest] (scan) Existing nested map key found '%s', checking value ..", key);
            v = &map.via.map.ptr[i].val;

            if (v->type != MSGPACK_OBJECT_ARRAY) {
              flb_error("[filter_nest] (scan) Nest_to key '%s' found but it is not a map, aborting", key);
            } else {
              flb_info("[filter_nest] (scan) Nest_to key '%s'", key);
              // clone into nest_map
            }
        } else if (strncmp(key, ctx->wildcard, klen) == 0) {
          keys_to_nest++;
        } else {
          keys_to_keep++;
        }

        k = NULL;
    }

    keys_to_nest++; // for the nest key

    // msgpack_pack_map(packer, keys_to_keep);
    // msgpack_pack_map(&nest_packer, keys_to_nest);

    // Create the new map from the previous values
    //  - Add wildcard matches to nest_map
    //  - Add others to map_out
    for (i = 0; i < map.via.map.size; i++) {
        k = &map.via.map.ptr[i].key;

        if (k->type == MSGPACK_OBJECT_BIN) {
            key = (char *) k->via.bin.ptr;
            klen = k->via.bin.size;
        } else if (k->type == MSGPACK_OBJECT_STR) {
            key  = (char *) k->via.str.ptr;
            klen = k->via.str.size;
        } else {
            continue;
        }

        // flb_debug("XX nest_data II : iteration %d - key is %s\n", i, key);

        matched = false;
        if (ctx->wildcard_is_dynamic) {
          // this will positively match "ABC123" with wildcard "ABC*" 
          matched = (strncmp(key, ctx->wildcard, ctx->wildcard_len) == 0);
        } else {
          // this will positively match "ABC" with wildcard "ABC" 
          matched = (
              (ctx->wildcard_len == klen) &&
              (strncmp(key, ctx->wildcard, ctx->wildcard_len) == 0)
             );
        }

        if (matched) {
            flb_debug("[filter_nest] We have a match for key '%s' to nest '%s'", ctx->wildcard, ctx->nesting_key);
            pack_string(&nest_packer, key);
            pack_string(&nest_packer, key); // XX pack value

        } else {
            flb_debug("[filter_nest] No match, adding to top-level");
            
            pack_string(packer, key);
            pack_string(packer, key); // XX pack value
        }

        pack_string(packer, ctx->nesting_key);
        pack_string(packer, ctx->nesting_key); // XX pack nest_map

        k = NULL;
    }

}

static void nest_map_data(msgpack_packer *packer,
    msgpack_object_map *map, 
    struct filter_nest_ctx *ctx) 
{

}

static int cb_nest_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    struct filter_nest_ctx *ctx;

    /* Create context */
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
    msgpack_object map;
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

    // Records come in in  the format,
    //
    // [ TIMESTAMP, { K1:V1, K2:V2 ...} ], 
    // [ TIMESTAMP, { K1:V1, K2:V2 ...} ]
    // ex,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]
    //
    // Loop is,
    //  - Check object type 
    //  - If Array :
    //    - Remove timestamp
    //    - Process embedded object with kv pairs with nesting rules
    //  - Else Log and skip

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
          flb_debug("[filter_nest] Record is an array");
          msgpack_object_print(stdout, result.data);

          // 0 = Timestamp
          // 1 = Embedded object
          map  = result.data.via.array.ptr[1];
          // nest_data(&packer, map, context);

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
