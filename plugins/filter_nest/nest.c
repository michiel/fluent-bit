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
    char *tmp;

    ctx->nest_under_key = NULL;
    ctx->key_wildcard = NULL;

    /* Nest key name */
    tmp = flb_filter_get_property("Nest_under", f_ins);
    if (tmp) {
        ctx->nest_under_key = flb_strdup(tmp);
        ctx->nest_under_key_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] Key \"Nest_under\" is missing\n");
        return -1;
    }

    /* Wildcard key name */
    tmp = flb_filter_get_property("Wildcard", f_ins);
    if (tmp) {
        ctx->key_wildcard = flb_strdup(tmp);
        ctx->key_wildcard_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] Key \"Regex\" is missing\n");
        return -1;
    }

    return 0;
}

static inline int clone_map(msgpack_packer *packer, msgpack_object_array *from, msgpack_object *to) {
  return 0;
}

static inline msgpack_object nest_data(msgpack_object map, struct filter_nest_ctx *ctx)
{

    int i;
    int klen;
    int vlen;
    char *key;
    char *val;
    msgpack_object *k;
    msgpack_object *v;
    struct mk_list *head;

    msgpack_object map_out;

    msgpack_packer ret_packer;
    msgpack_sbuffer* ret_buffer = msgpack_sbuffer_new();
    msgpack_packer_init(&ret_packer, &ret_buffer, msgpack_sbuffer_write);

    msgpack_packer nest_packer;
    msgpack_sbuffer* nest_buffer = msgpack_sbuffer_new();
    msgpack_packer_init(&nest_packer, &nest_buffer, msgpack_sbuffer_write);

    /* Iterate each item array to see if the nest key exists
     *  - Create a new map if it does not exist
     *  - Assign the reference to the existing or new map, depending
     *  - Error out if the key exists and is not a map
     * */

    // Search for an existing map
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

        flb_debug("XX nest_data : iteration %d - key is %s\n", i, key);

        if (strncmp(key, ctx->nest_under_key, klen) == 0) {
            v = &map.via.map.ptr[i].val;

            flb_debug("[filter_nest] (scan) Existing nested map key found '%s', checking value ..", key);
            if (v->type != MSGPACK_OBJECT_ARRAY) {
              flb_error("[filter_nest] (scan) Nest_to key '%s' found but it is not a map, aborting", key);
            } else {
              flb_info("[filter_nest] (scan) Nest_to key '%s'", key);
              //
              // clone into nest_map
              //
            }

            break;
        }

        k = NULL;
    }

    // Create the new map from the previous values
    //  - Add wildcard matches to nest_map
    //  - Add others to map_out
    for (i = 0; i < map.via.map.size; i++) {
        flb_debug("nest_data : iterating # %d", i);
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

        flb_debug("nest_data : key is %s\n", key);

        if (strncmp(key, ctx->key_wildcard, klen) == 0) {
            flb_debug("[filter_nest] Houston we have a match for key '%s' to nest '%s'", 
                ctx->key_wildcard,
                ctx->nest_under_key
                );
            // Add to nest_map
        } else {
            // Add to map_out
        }

        k = NULL;
    }

    // Add nest_map to map_out

    return map_out;
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

    // This holds our new, nested object

    msgpack_sbuffer new_sbuf;
    msgpack_packer new_pck;

    struct filter_nest_ctx *ctx = context;

    // Create temporary msgpack buffer

    msgpack_sbuffer_init(&new_sbuf);
    msgpack_packer_init(&new_pck, &new_sbuf, msgpack_sbuffer_write);

    flb_debug("[filter_nest] Operating nest filter. Moving keys matching '%s' to '%s'", 
        ctx->key_wildcard,
        ctx->nest_under_key
        );

    // Records come in in  the format,
    //
    // [ TIMESTAMP, { K1 :V1, K2: V2 ...} ], 
    // [ TIMESTAMP, { K1 :V1, K2: V2 ...} ]
    //
    // Loop is,
    //  - Check object type 
    //  - If Array :
    //    - Remove timestamp
    //    - Process embedded object with kv pairs with nesting rules
    //  - Else Log and skip

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
      flb_debug("[filter_nest] Processing a record");
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
