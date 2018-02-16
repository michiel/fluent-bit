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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_regex.h"
#include "kube_property.h"

#include <stdio.h>
#include <msgpack.h>

static int cb_kube_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct flb_kube *ctx;
    (void) data;

    /* Create configuration context */
    ctx = flb_kube_conf_create(f_ins, config);
    if (!ctx) {
        return -1;
    }

    /* Initialize regex context */
    ret = flb_kube_regex_init(ctx);
    if (ret == -1) {
        flb_kube_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_filter_set_context(f_ins, ctx);

    /*
     * Get Kubernetes Metadata: we gather this at the beginning
     * as we need this information to process logs in Kubernetes
     * environment, otherwise the service should not start.
     */
    flb_kube_meta_init(ctx, config);

    return 0;
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
                if (n != 'a' && n != 'b' &&
                    n != 't' && n != 'n' &&
                    n != 'v' && n != 'f' &&
                    n != 'r') {
                    i++;
                }
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

static int pack_map_content(msgpack_packer *pck, msgpack_sbuffer *sbuf,
                            msgpack_object source_map,
                            char *kube_buf, size_t kube_size,
                            struct flb_kube_meta *meta,
                            struct flb_parser *parser,
                            struct flb_kube *ctx)
{
    int i;
    int ret;
    int new_size;
    int map_size;
    int size;
    int new_map_size = 0;
    int log_index = -1;
    int unesc_len = 0;
    int log_buf_entries = 0;
    size_t off = 0;
    char *tmp;
    void *log_buf = NULL;
    size_t log_size = 0;
    msgpack_unpacked result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object root;
    struct flb_time log_time;

    /* Original map size */
    map_size = source_map.via.map.size;

    /* If merge_log is enabled, we need to lookup the 'log' field */
    if (ctx->merge_log == FLB_TRUE) {
        for (i = 0; i < map_size; i++) {
            k = source_map.via.map.ptr[i].key;

            /* Validate 'log' field */
            if (k.via.str.size == 3 &&
                strncmp(k.via.str.ptr, "log", 3) == 0) {
                log_index = i;
                break;
            }
        }
    }

    /*
     * If a log_index exists, the application log content inside the Docker JSON
     * map is a escaped string. Proceed to reserve a temporal buffer and create
     * an unescaped version.
     */
    if (log_index != -1) {
        v = source_map.via.map.ptr[log_index].val;
        if (v.via.str.size >= ctx->unesc_buf_size) {
            new_size = v.via.str.size + 1;
            tmp = flb_realloc(ctx->unesc_buf, new_size);
            if (tmp) {
                ctx->unesc_buf = tmp;
                ctx->unesc_buf_size = new_size;
            }
            else {
                flb_errno();
                return -1;
            }
        }

        /*
         * Check where to cut the string if common ending bytes like \r or \n
         * exists.
         */
        size = v.via.str.size;
        for (i = size - 1; i > 0; i--) {
            if (v.via.str.ptr[i - 1] == '\\' &&
                (v.via.str.ptr[i] == 'n' || v.via.str.ptr[i] == 'r')) {
                size -= 2;
                i--;
            }
            else {
                break;
            }
        }

        /* Unescape application string */
        unesc_len = unescape_string((char *) v.via.str.ptr,
                                    size, &ctx->unesc_buf);

        ret = -1;
        if (parser) {
            ret = flb_parser_do(parser, ctx->unesc_buf, unesc_len,
                                &log_buf, &log_size, &log_time);
            if (ret >= 0) {
                if (flb_time_to_double(&log_time) == 0) {
                    flb_time_get(&log_time);
                }
            }
        }
        else {
            ret = flb_pack_json(ctx->unesc_buf, unesc_len,
                                (char **) &log_buf, &log_size);
        }

        if (ret == -1) {
            flb_debug("[filter_kube] could not merge log as requested");
        }
    }

    /* Determinate the size of the new map */
    new_map_size = map_size;

    /* If a merged json exists, check the number of entries in that new map */
    if (log_buf && log_index != -1) {
        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, log_buf, log_size, &off);
        root = result.data;
        log_buf_entries = root.via.map.size;
        msgpack_unpacked_destroy(&result);
    }

    /* Kubernetes metadata */
    if (kube_buf && kube_size > 0) {
        if (ctx->flat == FLB_FALSE) {
            new_map_size++;
        }
        else {
            off = 0;
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, kube_buf, kube_size, &off);
            root = result.data;

            new_map_size += root.via.map.size;
            new_map_size += meta->skip;

            msgpack_unpacked_destroy(&result);
        }
    }

    /* Start packaging the final map */
    if (ctx->merge_json_key != NULL) {
        /* Make room for one new key that will hold the original log entries */
        new_map_size++;
    }
    else {
        new_map_size += log_buf_entries;
    }
    msgpack_pack_map(pck, new_map_size);

    /* Original map */
    for (i = 0; i < map_size; i++) {
        k = source_map.via.map.ptr[i].key;
        v = source_map.via.map.ptr[i].val;

        /*
         * If the original 'log' field was unescaped and converted to
         * msgpack properly, re-pack the new string version to avoid
         * multiple escape sequences in outgoing plugins.
         */
        if (log_buf && log_index == i) {
            msgpack_pack_object(pck, k);
            msgpack_pack_str(pck, unesc_len);
            msgpack_pack_str_body(pck, ctx->unesc_buf, unesc_len);
        }
        else {
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
    }

    /* Merged JSON */
    if (log_buf && log_index != -1) {
        if (ctx->merge_json_key && log_buf_entries > 0) {
            msgpack_pack_str(pck, ctx->merge_json_key_len);
            msgpack_pack_str_body(pck, ctx->merge_json_key,
                                  ctx->merge_json_key_len);
            msgpack_pack_map(pck, log_buf_entries);
        }

        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, log_buf, log_size, &off);
        root = result.data;
        for (i = 0; i < log_buf_entries; i++) {
            k = root.via.map.ptr[i].key;
            v = root.via.map.ptr[i].val;
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
        msgpack_unpacked_destroy(&result);
        flb_free(log_buf);
    }

    /* Kubernetes */
    if (kube_buf && kube_size > 0) {
        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, kube_buf, kube_size, &off);
        root = result.data;

        if (ctx->flat == FLB_FALSE) {
            msgpack_pack_str(pck, 10);
            msgpack_pack_str_body(pck, "kubernetes", 10);
    
            map_size = root.via.map.size;
            map_size += meta->skip;

            /* Pack cached kube buf entries */
            msgpack_pack_map(pck, map_size);
            for (i = 0; i < root.via.map.size; i++) {
                k = root.via.map.ptr[i].key;
                v = root.via.map.ptr[i].val;
                msgpack_pack_object(pck, k);
                msgpack_pack_object(pck, v);
            }
        } else {
            char *key_ptr = NULL;
            size_t key_size = 0;

            for (i = 0; i < root.via.map.size; i++) {
                k = root.via.map.ptr[i].key;
                v = root.via.map.ptr[i].val;
                
                /* Key should be a string - otherwise ignore */
                if (k.type == MSGPACK_OBJECT_STR) {
                    key_ptr  = (char *) k.via.str.ptr;
                    key_size = k.via.str.size;
                    msgpack_pack_str(pck, key_size);
                    msgpack_pack_str_body(pck, key_ptr, key_size);
                    msgpack_pack_object(pck, v);
                }
            }
        }
        
        /*else {
            int i;
            char *ptr_key = NULL;
            char buf_key[256];
            msgpack_object *k;
            msgpack_object *v;
            for (i = 0; i < root.via.map.size; i++) {
                k = &root.via.map.ptr[i].key;
                v = &root.via.map.ptr[i].val;
                ptr_key = NULL;
        
                /* Store key 
                char *key_ptr = NULL;
                size_t key_size = 0;
                size_t new_key_size = 0;

                /* Prefix and Delimiter 
                size_t prefix_size = strlen(ctx->flat_prefix);
                size_t delimiter_size = strlen(ctx->flat_delimiter);
                size_t buff_size = sizeof(buf_key) - 1;
                buff_size -= prefix_size;
                buff_size -= delimiter_size;

                if (k->type == MSGPACK_OBJECT_STR) {
                    key_ptr  = (char *) k->via.str.ptr;
                    key_size = k->via.str.size;
                    new_key_size += key_size;
                    new_key_size += prefix_size;
                    new_key_size += delimiter_size;

                    if (key_size < buff_size) {
                        strcpy(buf_key, ctx->flat_prefix);
                        strcat(buf_key, ctx->flat_delimiter);
                        strcat(buf_key, key_ptr);

                        buf_key[new_key_size] = '\0';
                        ptr_key = buf_key;
                    }
                    else {
                        /* Long map keys have a performance penalty 
                        ptr_key = flb_malloc(new_key_size + 1);
                        strcpy(ptr_key, ctx->flat_prefix);
                        strcat(ptr_key, ctx->flat_delimiter);
                        strcat(ptr_key, key_ptr);
                        ptr_key[new_key_size] = '\0';
                    }

                     /* Append the key 
                    msgpack_pack_str(pck, new_key_size);
                    msgpack_pack_str_body(pck, ptr_key, new_key_size);

                    /* Release temporal key if was allocated 
                    if (ptr_key && ptr_key != buf_key) {
                        flb_free(ptr_key);
                    }
                    ptr_key = NULL;

                    msgpack_pack_object(pck, *v);
                }
            }
        } */
        msgpack_unpacked_destroy(&result);

        char buf_key[256];
        size_t buf_size = 0;
        /* Pack meta */
        if (meta->container_name != NULL) {
            if (ctx->flat == FLB_FALSE) {
                msgpack_pack_str(pck, 14);
                msgpack_pack_str_body(pck, "container_name", 14);
            } 
            else {
                strcpy(buf_key, ctx->flat_key_prefix);
                strcat(buf_key, "container_name");
                buf_size = strlen(buf_key);
    
                msgpack_pack_str(pck, buf_size);
                msgpack_pack_str_body(pck, buf_key, buf_size);
            }
            msgpack_pack_str(pck, meta->container_name_len);
            msgpack_pack_str_body(pck, meta->container_name,
                                  meta->container_name_len);
        }
        if (meta->docker_id != NULL) {
            if (ctx->flat == FLB_FALSE) {
                msgpack_pack_str(pck, 9);
                msgpack_pack_str_body(pck, "docker_id", 9);
            } 
            else {
                strcpy(buf_key, ctx->flat_key_prefix);
                strcat(buf_key, "docker_id");
                buf_size = strlen(buf_key);
    
                msgpack_pack_str(pck, buf_size);
                msgpack_pack_str_body(pck, buf_key, buf_size);
            }
            msgpack_pack_str(pck, meta->docker_id_len);
            msgpack_pack_str_body(pck, meta->docker_id,
                                  meta->docker_id_len);
        }
        if (meta->container_hash != NULL) {
            if (ctx->flat == FLB_FALSE) {
                msgpack_pack_str(pck, 14);
                msgpack_pack_str_body(pck, "container_hash", 14);
            } 
            else {
                strcpy(buf_key, ctx->flat_key_prefix);
                strcat(buf_key, "container_hash");
                buf_size = strlen(buf_key);
    
                msgpack_pack_str(pck, buf_size);
                msgpack_pack_str_body(pck, buf_key, buf_size);
            }
            msgpack_pack_str(pck, meta->container_hash_len);
            msgpack_pack_str_body(pck, meta->container_hash,
                                  meta->container_hash_len);
        }
    }

    return 0;
}

static int cb_kube_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int ret;
    size_t off = 0;
    char *cache_buf = NULL;
    size_t cache_size = 0;
    msgpack_unpacked result;
    msgpack_object time;
    msgpack_object map;
    msgpack_object root;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_parser *parser = NULL;
    struct flb_kube *ctx = filter_context;
    struct flb_kube_meta meta = {0};
    struct flb_kube_props props = {0};

    (void) f_ins;
    (void) config;

    /* Check if we have some cached metadata for the incoming events */
    ret = flb_kube_meta_get(ctx,
                            tag, tag_len,
                            data, bytes,
                            &cache_buf, &cache_size, &meta, &props);
    if (ret == -1) {
        flb_kube_prop_destroy(&props);
        return FLB_FILTER_NOTOUCH;
    }

    if (props.parser != NULL) {
        parser = flb_parser_get(props.parser, config);
    }

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and append meta */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* get time and map */
        time = root.via.array.ptr[0];
        map  = root.via.array.ptr[1];

        /* Compose the new array */
        msgpack_pack_array(&tmp_pck, 2);
        msgpack_pack_object(&tmp_pck, time);

        ret = pack_map_content(&tmp_pck, &tmp_sbuf,
                               map,
                               cache_buf, cache_size,
                               &meta, parser, ctx);
        if (ret != 0) {
            msgpack_sbuffer_destroy(&tmp_sbuf);
            msgpack_unpacked_destroy(&result);
            if (ctx->dummy_meta == FLB_TRUE) {
                flb_free(cache_buf);
            }

            flb_kube_prop_destroy(&props);
            return FLB_FILTER_NOTOUCH;
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Release meta fields */
    flb_kube_meta_release(&meta);

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_free(cache_buf);
    }

    flb_kube_prop_destroy(&props);
    return FLB_FILTER_MODIFIED;
}

static int cb_kube_exit(void *data, struct flb_config *config)
{
    struct flb_kube *ctx;

    ctx = data;
    flb_kube_conf_destroy(ctx);

    return 0;
}

struct flb_filter_plugin filter_kubernetes_plugin = {
    .name         = "kubernetes",
    .description  = "Filter to append Kubernetes metadata",
    .cb_init      = cb_kube_init,
    .cb_filter    = cb_kube_filter,
    .cb_exit      = cb_kube_exit,
    .flags        = 0
};
