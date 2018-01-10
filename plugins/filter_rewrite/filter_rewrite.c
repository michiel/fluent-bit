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
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>
#include "filter_modifier.h"

#define PLUGIN_NAME "filter_rewrite"

static int configure(struct filter_rewrite_ctx *ctx,
                     struct flb_filter_instance *f_ins)


static int delete_list(struct filter_rewrite_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct modifier_record *record;

    mk_list_foreach_safe(head, tmp, &ctx->rewrite_rules) {
        record = mk_list_entry(head, struct modifier_record,  _head);
        flb_free(record->key);
        flb_free(record->val);
        mk_list_del(&record->_head);
        flb_free(record);
    }

    return 0;
}


static int cb_rewrite_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    struct filter_rewrite_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct filter_rewrite_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->rewrite_rules);

    if ( configure(ctx, f_ins) < 0 ){
        delete_list(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_rewrite_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *f_ins,
                          void *context,
                          struct flb_config *config)
{
    struct record_rewrite_ctx *ctx = context;

    return 0;
}

static int cb_rewrite_exit(void *data, struct flb_config *config)
{
    struct filter_rewrite_ctx *ctx = data;

    if (ctx != NULL) {
        delete_list(ctx);
        flb_free(ctx);
    }
    return 0;
}

struct flb_filter_plugin filter_rewrite_plugin = {
    .name         = "rewrite",
    .description  = "rewrite record",
    .cb_init      = cb_rewrite_init,
    .cb_filter    = cb_rewrite_filter,
    .cb_exit      = cb_rewrite_exit,
    .flags        = 0
};
