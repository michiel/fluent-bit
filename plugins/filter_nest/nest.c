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

static int msgpackobj2char(msgpack_object *obj,
                           char **ret_char, int *ret_char_size)
{
    int ret = -1;

    if (obj->type == MSGPACK_OBJECT_STR) {
        *ret_char      = (char*)obj->via.str.ptr;
        *ret_char_size = obj->via.str.size;
        ret = 0;
    }
    else if (obj->type == MSGPACK_OBJECT_BIN) {
        *ret_char      = (char*)obj->via.bin.ptr;
        *ret_char_size = obj->via.bin.size;
        ret = 0;
    }

    return ret;
}

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
    tmp = flb_filter_get_property("target_nest_key", f_ins);
    if (tmp) {
        ctx->target_nest_key_name = flb_strdup(tmp);
        ctx->target_nest_key_name_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] \"target_nest_key\" is missing\n");
        return -1;
    }

    /* Regex key name */
    tmp = flb_filter_get_property("regex_key", f_ins);
    if (tmp) {
        ctx->regex_key_name = flb_strdup(tmp);
        ctx->regex_key_name_len = strlen(tmp);
    } else {
        flb_error("[filter_parser] \"regex_key\" is missing\n");
        return -1;
    }

    return 0;
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
    int ret = FLB_FILTER_MODIFIED;
    int old_size = 0;
    int new_size = 0;
    msgpack_unpacked result;
    // msgpack_object map;
    msgpack_object root;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);



    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        old_size++;
        // post modification
        new_size++;

    }
    msgpack_unpacked_destroy(&result);

    /* we keep everything ? */
    if (old_size == new_size) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return ret;
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
