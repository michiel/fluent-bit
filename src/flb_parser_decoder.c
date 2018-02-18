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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

int octal_digit(char c)
{
    return (c >= '0' && c <= '7');
}

int hex_digit(char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f'));
}

int u8_wc_toutf8(char *dest, u_int32_t ch)
{
    if (ch < 0x80) {
        dest[0] = (char)ch;
        return 1;
    }
    if (ch < 0x800) {
        dest[0] = (ch>>6) | 0xC0;
        dest[1] = (ch & 0x3F) | 0x80;
        return 2;
    }
    if (ch < 0x10000) {
        dest[0] = (ch>>12) | 0xE0;
        dest[1] = ((ch>>6) & 0x3F) | 0x80;
        dest[2] = (ch & 0x3F) | 0x80;
        return 3;
    }
    if (ch < 0x110000) {
        dest[0] = (ch>>18) | 0xF0;
        dest[1] = ((ch>>12) & 0x3F) | 0x80;
        dest[2] = ((ch>>6) & 0x3F) | 0x80;
        dest[3] = (ch & 0x3F) | 0x80;
        return 4;
    }
    return 0;
}

/* assumes that src points to the character after a backslash
   returns number of input characters processed */
int u8_read_escape_sequence(char *str, u_int32_t *dest)
{
    u_int32_t ch;
    char digs[9]="\0\0\0\0\0\0\0\0";
    int dno=0, i=1;

    ch = (u_int32_t)str[0];    /* take literal character */

    if (str[0] == 'n')
        ch = L'\n';
    else if (str[0] == 't')
        ch = L'\t';
    else if (str[0] == 'r')
        ch = L'\r';
    else if (str[0] == 'b')
        ch = L'\b';
    else if (str[0] == 'f')
        ch = L'\f';
    else if (str[0] == 'v')
        ch = L'\v';
    else if (str[0] == 'a')
        ch = L'\a';
    else if (octal_digit(str[0])) {
        i = 0;
        do {
            digs[dno++] = str[i++];
        } while (octal_digit(str[i]) && dno < 3);
        ch = strtol(digs, NULL, 8);
    }
    else if (str[0] == 'x') {
        while (hex_digit(str[i]) && dno < 2) {
            digs[dno++] = str[i++];
        }
        if (dno > 0)
            ch = strtol(digs, NULL, 16);
    }
    else if (str[0] == 'u') {
        while (hex_digit(str[i]) && dno < 4) {
            digs[dno++] = str[i++];
        }
        if (dno > 0)
            ch = strtol(digs, NULL, 16);
    }
    else if (str[0] == 'U') {
        while (hex_digit(str[i]) && dno < 8) {
            digs[dno++] = str[i++];
        }
        if (dno > 0)
            ch = strtol(digs, NULL, 16);
    }
    *dest = ch;

    return i;
}

inline bool is_json_escape(char *c)
{
  return (
        (*c == '\"') || // double-quote
        (*c == '\'') || // single-quote
        (*c == '\\') || // solidus
        (*c == '/')     // reverse-solidus
      );
}

/* convert a string with literal \uxxxx or \Uxxxxxxxx characters to UTF-8
   example: u8_unescape(mybuf, 256, "hello\\u220e")
   note the double backslash is needed if called on a C string literal */
int u8_unescape(char *buf, int sz, char *src)
{
    u_int32_t ch;
    char temp[4];
    char *next;

    int count_out = 0;
    int count_in = 0;
    int esc_in = 0;
    int esc_out = 0;

    while (*src && count_in < sz) {
        next = src + 1;
        if (*src == '\\' && !is_json_escape(next)) {
            esc_in = u8_read_escape_sequence((src + 1), &ch) + 1;
        }
        else {
            ch = (u_int32_t)*src;
            esc_in = 1;
        }

        src += esc_in;
        count_in += esc_in;

        esc_out = u8_wc_toutf8(temp, ch);

        if (esc_out > sz-count_out) {
            flb_error("Crossing over string boundary");
            break;
        }
        memcpy(&buf[count_out], temp, esc_out);
        count_out += esc_out;
    }
    if (count_in < sz) {
        flb_error("Not at boundary but still NULL terminating : %d - '%s'", sz, src);
    }
    buf[count_in - 1] = '\0';
    return count_out;
}

static int unescape_string(char *buf, int buf_len, char **unesc_buf)
{
    int i = 0;
    int j = 0;
    char *p;
    char n;

    p = *unesc_buf;
    while (i < buf_len) {
        if (buf[i] == '\\') {
            if (i + 1 < buf_len) {
                n = buf[i + 1];
                if (n == 'n') {
                    p[j++] = '\n';
                    i++;
                }
                else if (n == 'a') {
                    p[j++] = '\a';
                    i++;
                }
                else if (n == 'b') {
                    p[j++] = '\b';
                    i++;
                }
                else if (n == 't') {
                    p[j++] = '\t';
                    i++;
                }
                else if (n == 'v') {
                    p[j++] = '\v';
                    i++;
                }
                else if (n == 'f') {
                    p[j++] = '\f';
                    i++;
                }
                else if (n == 'r') {
                    p[j++] = '\r';
                    i++;
                }
                i++;
                continue;
            }
            else {
                i++;
            }
        }
        p[j++] = buf[i++];
    }
    p[j] = '\0';
    return j;
}

/*
 * Given a msgpack map, apply the parser-decoder rules defined and generate
 * a new msgpack buffer.
 */
int flb_parser_decoder_do(struct mk_list *decoders,
                          char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size)
{
    int i;
    int len;
    int ret;
    int matched;
    size_t off = 0;
    char *buf;
    size_t size;
    char *tmp;
    struct mk_list *head;
    struct flb_parser_dec *dec;
    msgpack_object k;
    msgpack_object v;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;

    /* Initialize unpacker */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, in_buf, in_size, &off);
    map = result.data;

    if (map.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /*
     * First check if any field in the record matches a decoder rule. It's
     * better to check this before hand otherwise we need to jump directly
     * to create a "possible new outgoing buffer".
     */
    matched = -1;
    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;
        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        /* Try to match this key name with decoder's rule */
        mk_list_foreach(head, decoders) {
            dec = mk_list_entry(head, struct flb_parser_dec, _head);
            if (dec->key_len == k.via.str.size &&
                strncmp(dec->key_name, k.via.str.ptr, dec->key_len) == 0) {
                /* we have a match, stop the check */
                matched = i;
                break;
            }
            else {
                matched = -1;
            }
        }

        if (matched >= 0) {
            break;
        }
    }

    /* No matches, no need to continue */
    if (matched == -1) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* Create new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Register the map (same size) */
    msgpack_pack_map(&mp_pck, map.via.map.size);

    /* Compose new outgoing buffer */
    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;

        /* Pack right away previous fields in the map */
        if (i < matched) {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
            continue;
        }

        /* Process current key names and decoder rules */
        if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_STR) {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
            continue;
        }

        /* Check if the current key name matches some decoder rule */
        bool value_has_been_changed = false;
        buf = NULL;
        mk_list_foreach(head, decoders) {
            dec = mk_list_entry(head, struct flb_parser_dec, _head);
            if (dec->key_len != k.via.str.size ||
                strncmp(dec->key_name, k.via.str.ptr, dec->key_len) != 0) {
                continue;
            }

            // flb_debug("Decoder rule matched key '%s'", dec->key_name);
            /* We got a match: 'key name' == 'decoder field name' */

            if (dec->buf_size < v.via.str.size) {
                tmp = flb_realloc(dec->buf_data, v.via.str.size);

                if (!tmp) {
                    flb_errno();
                    break;
                }

                dec->buf_data = tmp;
                dec->buf_size = v.via.str.size;
            }

            if (dec->type == FLB_PARSER_DEC_JSON) {
              flb_debug("[parser_dec] Decoding JSON");
              len = unescape_string((char *) v.via.str.ptr, v.via.str.size,
                                    &dec->buf_data);
              ret = flb_pack_json(dec->buf_data, len, &buf, &size);
              if (ret != 0) {
                  flb_debug("[parser_dec] field %s is not JSON",
                            dec->key_name);
                  break;
              }
              msgpack_pack_object(&mp_pck, k);
              msgpack_sbuffer_write(&mp_sbuf, buf, size);

              value_has_been_changed = true;

            } else if (dec->type == FLB_PARSER_DEC_UNESCAPE_UTF8) {
              // flb_debug("[parser_dec] Unescaping UTF-8");

              msgpack_pack_object(&mp_pck, k);

              len = u8_unescape(
                  (char *) dec->buf_data,
                  v.via.str.size,
                  (char *) v.via.str.ptr
                  );

              // flb_debug("Bump count is %d for '%s'", len, dec->buf_data);

              // len = v.via.str.size - len; 

              msgpack_pack_str(&mp_pck, len);
              msgpack_pack_str_body(&mp_pck, dec->buf_data, len);

              value_has_been_changed = true;

            } else {
              flb_debug("[parser_dec: No match");
            }
            
            break;

        }

        if (buf) {
            flb_free(buf);
            buf = NULL;
        }

        if (!value_has_been_changed) {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
        }

    }

    msgpack_unpacked_destroy(&result);
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

struct mk_list *flb_parser_decoder_list_create(struct mk_rconf_section *section)
{
    int c = 0;
    int type;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct mk_list *list = NULL;
    struct mk_list *split;
    struct flb_split_entry *decoder;
    struct flb_split_entry *field;
    struct flb_parser_dec *dec;

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        if (strcasecmp(entry->key, "Decode_Field") != 0) {
            continue;
        }

        /* Split the value */
        split = flb_utils_split(entry->val, ' ', 1);
        if (!split) {
            flb_error("[parser] invalid number of parameters in decoder");
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* We expect two values: decoder name and target field */
        if (mk_list_size(split) != 2) {
            flb_error("[parser] invalid number of parameters in decoder");
            flb_utils_split_free(split);
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Get entry references */
        decoder = mk_list_entry_first(split, struct flb_split_entry, _head);
        field = mk_list_entry_last(split, struct flb_split_entry, _head);

        /* Get decoder */
        if (strcasecmp(decoder->value, "json") == 0) {
            type = FLB_PARSER_DEC_JSON;
        }
        else if (strcasecmp(decoder->value, "unescape_utf8") == 0) {
            type = FLB_PARSER_DEC_UNESCAPE_UTF8;
        }
        else {
            flb_error("[parser] field decoder '%s' unknown", decoder->value);
            flb_utils_split_free(split);
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Create decoder context */
        dec = flb_malloc(sizeof(struct flb_parser_dec));
        if (!dec) {
            flb_errno();
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        dec->type = type;
        dec->key_name = flb_strdup(field->value);
        dec->key_len  = strlen(field->value);
        dec->buf_data = flb_malloc(FLB_PARSER_DEC_BUF_SIZE);
        dec->buf_size = FLB_PARSER_DEC_BUF_SIZE;

        /* Remove temporal split */
        flb_utils_split_free(split);

        if (!dec->buf_data) {
            flb_errno();
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        mk_list_add(&dec->_head, list);
        c++;
    }

    if (c == 0) {
        flb_free(list);
        return NULL;
    }

    return list;
}

int flb_parser_decoder_list_destroy(struct mk_list *list)
{
    int c = 0;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_parser_dec *dec;

    mk_list_foreach_safe(head, tmp, list) {
        dec = mk_list_entry(head, struct flb_parser_dec, _head);
        mk_list_del(&dec->_head);
        flb_free(dec->key_name);
        flb_free(dec->buf_data);
        flb_free(dec);
        c++;
    }

    flb_free(list);
    return c;
}
