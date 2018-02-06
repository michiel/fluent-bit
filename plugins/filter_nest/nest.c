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

static int cb_nest_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct nest_ctx *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct nest_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->rules);

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
