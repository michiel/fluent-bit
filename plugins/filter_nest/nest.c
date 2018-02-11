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

static int configure(struct filter_nest_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    int ret;
    struct flb_config_prop *prop = NULL;
    char *tmp;

    ctx->target_nest_key_name = NULL;
    ctx->regex_key_name = NULL;

    /* Nest key name */
    tmp = flb_filter_get_property("Nest_in", f_ins);
    if (tmp) {
        ctx->target_nest_key_name = flb_strdup(tmp);
        ctx->target_nest_key_name_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] \"target_nest_key\" is missing\n");
        return -1;
    }

    /* Regex key name */
    tmp = flb_filter_get_property("Regex", f_ins);
    if (tmp) {
        ctx->regex_key_name = flb_strdup(tmp);
        ctx->regex_key_name_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] \"regex_key\" is missing\n");
        return -1;
    }

    return 0;
}

static inline msgpack_object nest_data(msgpack_object map, struct nest_ctx *ctx)
{

    int i;
    int ret;
    int klen;
    int vlen;
    char *key;
    char *val;
    msgpack_object *k;
    msgpack_object *v;
    struct mk_list *head;

    msgpack_sbuffer new_sbuf;
    msgpack_packer new_pck;

    msgpack_sbuffer_init(&new_sbuf);
    msgpack_packer_init(&new_pck, &new_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array to see if the nest key exists
     *  - Create a new map if it does not exist
     *  - Assign the reference to the existing or new map, depending
     *  - Error out if the key exists and is not a map
     * */

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);

        /* Lookup target key/value */
        for (i = 0; i < map.via.map.size; i++) {
            k = &map.via.map.ptr[i].key;

            if (k->type != MSGPACK_OBJECT_BIN &&
                k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k->type == MSGPACK_OBJECT_STR) {
                key  = (char *) k->via.str.ptr;
                klen = k->via.str.size;
            }
            else {
                key = (char *) k->via.bin.ptr;
                klen = k->via.bin.size;
            }

            if (strncmp(key, rule->field, klen) == 0) {
                break;
            }

            k = NULL;
        }
    }

    msgpack_unpacker_destroy(&new_pck);
    return new_sbuf;
}


static int cb_nest_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret = 0;
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
    return ret;
}

static int cb_nest_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *f_ins,
                          void *context,
                          struct flb_config *config)
{
    msgpack_unpacked result;
    // msgpack_object map;
    msgpack_object root;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    // This holds our new, nested object

    msgpack_sbuffer new_sbuf;
    msgpack_packer new_pck;

    struct filter_nest_ctx *ctx = context;

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&new_sbuf);
    msgpack_packer_init(&new_pck, &new_sbuf, msgpack_sbuffer_write);

    flb_debug("[filter_nest] Operating nest filter. Moving keys matching '%s' to '%s'", 
        ctx->regex_key_name,
        ctx->target_nest_key_name
        );

    // Records come in in  the format,
    // [ TIMESTAMP, { K1 :V1, K2: V2 ...} ]
    // Loop is,
    //  - Check object type 
    //  - If Array :
    //    - Remove timestamp
    //    - Process embedded object with kv pairs with nesting rules
    //  - Else Log and skip

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
      flb_debug("[filter_nest] Processing a record %s");
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
          flb_debug("[filter_nest] Record is an object array");

          // 0 = Timestamp
          // 1 = Embedded object
          map  = result.data.via.array.ptr[1];

          // Process the embedded object into a nested one, add that to our new array
          msgpack_pack_object(&new_pck, nest_data(map, context));

        } else {
          flb_debug("[filter_nest] Record is a NOT or map or array");
          continue;
        }
    }
    msgpack_unpacked_destroy(&result);

    //
    // Clean up the packer, leave the new_sbuf and hand it back
    //

    msgpack_unpacker_destroy(&new_pck);

    *out_buf   = new_sbuf.data;
    *out_size = new_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_nest_exit(void *data, struct flb_config *config)
{
    struct nest_ctx *ctx = data;

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
