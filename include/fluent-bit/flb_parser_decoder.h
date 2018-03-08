/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#ifndef FLB_PARSER_DECODER_H
#define FLB_PARSER_DECODER_H

#include <fluent-bit/flb_info.h>
#include <monkey/mk_core.h>

/* Decoder types */
#define FLB_PARSER_DEC_JSON  0
#define FLB_PARSER_DEC_UNESCAPE_UTF8  1

#define FLB_PARSER_DEC_BUF_SIZE 1024*8  /* 8KB */

struct flb_parser_dec {
    int type;

    /* Key name */
    int key_len;
    char *key_name;

    /* Temporal buffer for data decoding */
    char *buf_data;
    size_t buf_size;

    /* Link to parser->decoders list */
    struct mk_list _head;
};

struct mk_list *flb_parser_decoder_list_create(struct mk_rconf_section *section);
int flb_parser_decoder_list_destroy(struct mk_list *list);
int flb_parser_decoder_do(struct mk_list *decoders,
                          char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size);

#endif
