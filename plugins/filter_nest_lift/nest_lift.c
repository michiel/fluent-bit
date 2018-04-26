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

#include "nest_lift.h"

static int configure(struct filter_nest_lift_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    char *tmp;

    ctx->nested_under = NULL;
    ctx->prefix_with = NULL;

    tmp = flb_filter_get_property("nested_under", f_ins);
    if (tmp) {
        ctx->nested_under = flb_strdup(tmp);
        ctx->nested_under_len = strlen(tmp);
    }
    else {
        flb_error("[filter_nest_lift] Key \"nested_under\" is missing\n");
        return -1;
    }

    tmp = flb_filter_get_property("prefix_with", f_ins);
    if (tmp != NULL) {
        ctx->prefix_with = flb_strdup(tmp);
        ctx->prefix_with_len = strlen(tmp);
        ctx->use_prefix = FLB_TRUE;
    }
    else {
        ctx->prefix_with = NULL;
        ctx->prefix_with_len = 0;
        ctx->use_prefix = FLB_FALSE;
    }

    return 0;
}

static void helper_pack_string(msgpack_packer *packer, const char *str, int len)
{
    if (str == NULL) {
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static inline void map_pack_each_if(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct filter_nest_lift_ctx *ctx,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_nest_lift_ctx * ctx)
    )
{
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline bool is_kv_to_lift(msgpack_object_kv * kv,
                                 struct filter_nest_lift_ctx *ctx)
{

    char *key;
    int klen;

    msgpack_object *obj = &kv->key;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        // If the key is not something we can match on then we leave it alone
        return false;
    }

    return ((ctx->nested_under_len == klen) &&
        (strncmp(key, ctx->nested_under, klen) == 0)
        );
}

static inline bool is_not_kv_to_lift(msgpack_object_kv * kv,
                                     struct filter_nest_lift_ctx *ctx)
{
    return !is_kv_to_lift(kv, ctx);
}

static inline int map_count_if(msgpack_object * map,
                            struct filter_nest_lift_ctx *ctx,
                            bool(*f) (msgpack_object_kv * kv,
                                      struct filter_nest_lift_ctx * ctx)
    )
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            count++;
        }
    }
    return count;
}

static inline void apply_nest_lifting_rules(msgpack_packer * packer,
                                       msgpack_object * root,
                                       struct filter_nest_lift_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    // * Record array init(2)
    msgpack_pack_array(packer, 2);

    // * * Record array item 1/2
    msgpack_pack_object(packer, ts);

    /*
    int i;

    for (i = 0; i < map->via.map.size; i++) {
      msgpack_object *obj = &kv->key;
      if ((*f) (&map->via.map.ptr[i], ctx)) {
        count++;
      }
    }
    */

    size_t keys_to_lift_from_count = map_count_if(&map, ctx, &is_kv_to_lift);
    size_t items_toplevel_count =
      (map.via.map.size - keys_to_lift_from_count + 0);

    flb_debug ("[filter_nest_lift] Outer map size %d elements",
        items_toplevel_count);

    // * * Record array item 2/2
    // * * Create a new map with toplevel ( current items -1 ) + (size of map to lift)
    msgpack_pack_map(packer, items_toplevel_count);

    // * * Pack all current top-level items
    map_pack_each_if(packer, &map, ctx, &is_not_kv_to_lift);

    /*
    // * * * Lift the map (if any)
    helper_pack_string(packer, ctx->lift_, ctx->nesting_key_len);

    // * * * Create the nest map value
    msgpack_pack_map(packer, items_to_nest_count);

    // * * * * Pack the nested items
    map_pack_each_if(packer, &map, ctx, &is_kv_to_lift);
    */
}

static int cb_nest_lift_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config, void *data)
{
    struct filter_nest_lift_ctx *ctx;

    // Create context
    ctx = flb_malloc(sizeof(struct filter_nest_lift_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    if (configure(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    // Set context
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_nest_lift_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t * out_size,
                          struct flb_filter_instance *f_ins,
                          void *context, struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    struct filter_nest_lift_ctx *ctx = context;

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    if (ctx->use_prefix) {
      flb_debug("[filter_nest_lift] Lifting key matching '%s' without prefix",
                ctx->nested_under);
    } else {
      flb_debug("[filter_nest_lift] Lifting key matching '%s' with prefix '%s'",
                ctx->nested_under, ctx->prefix_with);
    }


    // Records come in the format,
    //
    // [ TIMESTAMP, { K1=>V1, K2=>V2, ...} ],
    // [ TIMESTAMP, { K1=>V1, K2=>V2, ...} ]
    //
    // Example record,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            flb_debug("[filter_nest_lift] Record is an array, applying rules");
            apply_nest_lifting_rules(&packer, &result.data, ctx);
        }
        else {
            flb_debug("[filter_nest_lift] Record is NOT an array, skipping");
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_nest_lift_exit(void *data, struct flb_config *config)
{
    struct filter_nest_lift_ctx *ctx = data;

    flb_free(ctx->nested_under);
    flb_free(ctx->prefix_with);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_nest_lift_plugin = {
    .name = "nest_lift",
    .description = "lift nested events by specified field",
    .cb_init = cb_nest_lift_init,
    .cb_filter = cb_nest_lift_filter,
    .cb_exit = cb_nest_lift_exit,
    .flags = 0
};
