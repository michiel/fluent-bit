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

#include "modify.h"

static void teardown(struct filter_modify_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct modify_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct modify_rule, _head);
        flb_free(rule->key);
        flb_free(rule->val);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static void helper_pack_string(msgpack_packer * packer, const char *str,
                               int len)
{

    if (str == NULL) {
        flb_error("[filter_modify] helper_pack_string : NULL passed");
        msgpack_pack_nil(packer);
    }
    else if (len != strlen(str)) {
        flb_error
            ("[filter_modify] helper_pack_string : Incorrect LEN passed");
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static int setup(struct filter_modify_ctx *ctx,
                 struct flb_filter_instance *f_ins, struct flb_config *config)
{
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_config_prop *prop;
    struct modify_rule *rule;

    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        rule = flb_malloc(sizeof(struct modify_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        split = flb_utils_split(prop->val, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_error
                ("[filter_modify] Invalid value for operation %s, expected key and value",
                 prop->val);
            teardown(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        rule->key = flb_strndup(sentry->value, sentry->len);
        rule->key_len = sentry->len;

        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        rule->val = flb_strndup(sentry->value, sentry->len);
        rule->val_len = sentry->len;

        flb_utils_split_free(split);

        if (strcasecmp(prop->key, "rename") == 0) {
            rule->ruletype = RENAME;
        }
        else if (strcasecmp(prop->key, "hard_rename") == 0) {
            rule->ruletype = HARD_RENAME;
        }
        else if (strcasecmp(prop->key, "rewrite") == 0) {
            rule->ruletype = REWRITE;
        }
        else if (strcasecmp(prop->key, "hard_rewrite") == 0) {
            rule->ruletype = HARD_REWRITE;
        }
        else if (strcasecmp(prop->key, "add") == 0) {
            rule->ruletype = ADD;
        }
        else if (strcasecmp(prop->key, "set") == 0) {
            rule->ruletype = SET;
        }
        else if (strcasecmp(prop->key, "remove") == 0) {
            rule->ruletype = REMOVE;
        }
        else if (strcasecmp(prop->key, "remove_regex") == 0) {
            rule->ruletype = REMOVE_REGEX;
        }
        else if (strcasecmp(prop->key, "copy") == 0) {
            rule->ruletype = COPY;
        }
        else if (strcasecmp(prop->key, "hard_copy") == 0) {
            rule->ruletype = HARD_COPY;
        }
        else {
            flb_error
                ("[filter_modify] Invalid operation '%s' in configuration",
                 prop->key);
            teardown(ctx);
            flb_free(rule);
            return -1;
        }

        mk_list_add(&rule->_head, &ctx->rules);
        ctx->rules_cnt++;
    }

    return 0;
}

static inline bool helper_msgpack_object_matches_str(msgpack_object * obj,
                                                     char *str, int len)
{

    char *key;
    int klen;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        return false;
    }

    return ((len == klen) && (strncmp(str, key, klen) == 0)
        );
}

static inline bool kv_key_matches_str(msgpack_object_kv * kv,
                                      char *str, int len)
{
    return helper_msgpack_object_matches_str(&kv->key, str, len);
}

static inline bool kv_val_matches_str(msgpack_object_kv * kv,
                                      char *str, int len)
{
    return helper_msgpack_object_matches_str(&kv->val, str, len);
}

static inline bool kv_key_does_not_match_str(msgpack_object_kv * kv,
                                             char *str, int len)
{
    return !kv_key_matches_str(kv, str, len);
}

static inline bool kv_key_matches_rule_key(msgpack_object_kv * kv,
                                           struct modify_rule *rule)
{
    return kv_key_matches_str(kv, rule->key, rule->key_len);
}

static inline bool kv_key_does_not_match_rule_key(msgpack_object_kv * kv,
                                                  struct modify_rule *rule)
{
    return !kv_key_matches_rule_key(kv, rule);
}

static inline bool kv_key_matches_rule_val(msgpack_object_kv * kv,
                                           struct modify_rule *rule)
{
    return kv_key_matches_str(kv, rule->val, rule->val_len);
}

static inline bool kv_key_does_not_match_rule_val(msgpack_object_kv * kv,
                                                  struct modify_rule *rule)
{
    return !kv_key_matches_rule_val(kv, rule);
}

static inline int map_count_keys_matching_str(msgpack_object * map,
                                              char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (kv_key_matches_str(&map->via.map.ptr[i], str, len)) {
            count++;
        }
    }
    return count;
}

static inline int map_count_keys_not_matching_str(msgpack_object * map,
                                                  char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (!kv_key_matches_str(&map->via.map.ptr[i], str, len)) {
            count++;
        }
    }
    return count;
}

static inline int map_count_keys_matching_rule_key(msgpack_object * map,
                                                   struct modify_rule *rule)
{
    return map_count_keys_matching_str(map, rule->key, rule->key_len);
}

static inline int map_count_keys_not_matching_rule_key(msgpack_object * map,
                                                       struct modify_rule
                                                       *rule)
{
    return map_count_keys_not_matching_str(map, rule->key, rule->key_len);
}

static inline int map_count_keys_matching_rule_val(msgpack_object * map,
                                                   struct modify_rule *rule)
{
    return map_count_keys_matching_str(map, rule->val, rule->val_len);
}

static inline int map_count_keys_not_matching_rule_val(msgpack_object * map,
                                                       struct modify_rule
                                                       *rule)
{
    return map_count_keys_not_matching_str(map, rule->val, rule->val_len);
}

static inline void map_pack_each(msgpack_packer * packer,
                                 msgpack_object * map)
{
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        msgpack_pack_object(packer, map->via.map.ptr[i].key);
        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }
}

static inline void map_pack_each_fn(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct modify_rule *rule,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct modify_rule * rule)
    )
{
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], rule)) {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline int map_count_fn(msgpack_object * map,
                               struct modify_rule *ctx,
                               bool(*f) (msgpack_object_kv * kv,
                                         struct modify_rule * ctx)
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

static inline int apply_rule_RENAME(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct modify_rule *rule)
{
    int i;

    int match_keys = map_count_keys_matching_rule_key(map, rule);
    int conflict_keys = map_count_keys_matching_rule_val(map, rule);

    if (match_keys == 0) {
        flb_info
            ("[filter_modify] Rule RENAME %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 0) {
        flb_info
            ("[filter_modify] Rule RENAME %s TO %s : Existing key %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);
        for (i = 0; i < map->via.map.size; i++) {
            if (kv_key_matches_rule_key(&map->via.map.ptr[i], rule)) {
                helper_pack_string(packer, rule->val, rule->val_len);
            }
            else {
                msgpack_pack_object(packer, map->via.map.ptr[i].key);
            }
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_HARD_RENAME(msgpack_packer * packer,
                                         msgpack_object * map,
                                         struct modify_rule *rule)
{
    int i;

    int match_keys = map_count_keys_matching_rule_key(map, rule);
    int conflict_keys = map_count_keys_matching_rule_val(map, rule);
    msgpack_object_kv *kv;

    if (match_keys == 0) {
        flb_info
            ("[filter_modify] Rule HARD_RENAME %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys == 0) {
        msgpack_pack_map(packer, map->via.map.size);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            if (kv_key_matches_rule_key(kv, rule)) {
                helper_pack_string(packer, rule->val, rule->val_len);
            }
            else {
                msgpack_pack_object(packer, kv->key);
            }
            msgpack_pack_object(packer, kv->val);
        }
        return FLB_FILTER_MODIFIED;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size - conflict_keys);

        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            // If this kv->key matches rule->val it's a conflict source key and will be skipped
            if (!kv_key_matches_rule_val(kv, rule)) {
                if (kv_key_matches_rule_key(kv, rule)) {
                    helper_pack_string(packer, rule->val, rule->val_len);
                }
                else {
                    msgpack_pack_object(packer, kv->key);
                }

                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_COPY(msgpack_packer * packer,
                                  msgpack_object * map,
                                  struct modify_rule *rule)
{
    int match_keys = map_count_keys_matching_rule_key(map, rule);
    int conflict_keys = map_count_keys_matching_rule_val(map, rule);
    int i;
    msgpack_object_kv *kv;

    if (match_keys < 1) {
        flb_info
            ("[filter_modify] Rule COPY %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (match_keys > 1) {
        flb_info
            ("[filter_modify] Rule COPY %s TO %s : Multiple keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 0) {
        flb_info
            ("[filter_modify] Rule COPY %s TO %s : Existing keys matching target %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size + 1);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];

            msgpack_pack_object(packer, kv->key);
            msgpack_pack_object(packer, kv->val);

            if (kv_key_matches_rule_key(kv, rule)) {
                helper_pack_string(packer, rule->val, rule->val_len);
                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_HARD_COPY(msgpack_packer * packer,
                                       msgpack_object * map,
                                       struct modify_rule *rule)
{
    int i;

    int match_keys = map_count_keys_matching_rule_key(map, rule);
    int conflict_keys = map_count_keys_matching_rule_val(map, rule);
    msgpack_object_kv *kv;

    if (match_keys < 1) {
        flb_info
            ("[filter_modify] Rule HARD_COPY %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (match_keys > 1) {
        flb_warn
            ("[filter_modify] Rule HARD_COPY %s TO %s : Multiple keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 1) {
        flb_warn
            ("[filter_modify] Rule HARD_COPY %s TO %s : Multiple target keys matching %s found, not applying rule",
             rule->key, rule->val, rule->val);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys == 0) {
        msgpack_pack_map(packer, map->via.map.size + 1);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            msgpack_pack_object(packer, kv->key);
            msgpack_pack_object(packer, kv->val);

            // This is our copy
            if (kv_key_matches_rule_key(kv, rule)) {
                helper_pack_string(packer, rule->val, rule->val_len);
                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);

        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];

            // Skip the conflict key, we will create a new one
            if (!kv_key_matches_rule_val(kv, rule)) {
                msgpack_pack_object(packer, kv->key);
                msgpack_pack_object(packer, kv->val);

                // This is our copy
                if (kv_key_matches_rule_key(kv, rule)) {
                    helper_pack_string(packer, rule->val, rule->val_len);
                    msgpack_pack_object(packer, kv->val);
                }
            }
        }

        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_ADD(msgpack_packer * packer,
                                 msgpack_object * map,
                                 struct modify_rule *rule)
{
    if (map_count_keys_matching_rule_key(map, rule) == 0) {
        msgpack_pack_map(packer, map->via.map.size + 1);
        map_pack_each(packer, map);
        helper_pack_string(packer, rule->key, rule->key_len);
        helper_pack_string(packer, rule->val, rule->val_len);
        return FLB_FILTER_MODIFIED;
    }
    else {
        flb_info
            ("[filter_modify] Rule ADD %s : this key already exists, skipping",
             rule->key);
        return FLB_FILTER_NOTOUCH;
    }
}

static inline int apply_rule_SET(msgpack_packer * packer,
                                 msgpack_object * map,
                                 struct modify_rule *rule)
{
    int matches = map_count_keys_matching_rule_key(map, rule);

    msgpack_pack_map(packer, map->via.map.size - matches + 1);

    if (matches == 0) {
        map_pack_each(packer, map);
        helper_pack_string(packer, rule->key, rule->key_len);
        helper_pack_string(packer, rule->val, rule->val_len);
    }
    else {
        map_pack_each_fn(packer, map, rule, kv_key_does_not_match_rule_key);
        helper_pack_string(packer, rule->key, rule->key_len);
        helper_pack_string(packer, rule->val, rule->val_len);
    }

    return FLB_FILTER_MODIFIED;
}

static inline int apply_rule_REMOVE(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct modify_rule *rule)
{
    int matches = map_count_keys_matching_rule_key(map, rule);

    if (matches == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size - matches);
        map_pack_each_fn(packer, map, rule, kv_key_does_not_match_rule_key);
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_modifying_rule(msgpack_packer * packer,
                                       msgpack_object * map,
                                       struct modify_rule *rule)
{
    switch (rule->ruletype) {
    case RENAME:
        return apply_rule_RENAME(packer, map, rule);
    case HARD_RENAME:
        return apply_rule_HARD_RENAME(packer, map, rule);
//     case REWRITE:
//         return apply_rule_REWRITE(packer, map, rule);
//     case HARD_REWRITE:
//         return apply_rule_HARD_REWRITE(packer, map, rule);
    case ADD:
        return apply_rule_ADD(packer, map, rule);
    case SET:
        return apply_rule_SET(packer, map, rule);
    case REMOVE:
        return apply_rule_REMOVE(packer, map, rule);
//     case REMOVE_REGEX:
//         return apply_rule_REMOVE_REGEX(packer, map, rule);
    case COPY:
        return apply_rule_COPY(packer, map, rule);
    case HARD_COPY:
        return apply_rule_HARD_COPY(packer, map, rule);
    default:
        flb_warn
            ("[filter_modify] Unknown ruletype for rule with key %s, ignoring",
             rule->key);
    }
    return FLB_FILTER_NOTOUCH;
}

static inline void apply_modifying_rules(msgpack_packer * packer,
                                         msgpack_object * root,
                                         struct filter_modify_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    int records_in = map.via.map.size;

    struct modify_rule *rule;

    msgpack_sbuffer buffer;
    msgpack_packer loop_packer;
    msgpack_zone mempool;
    msgpack_object deserialized;

    struct mk_list *tmp;
    struct mk_list *head;

    msgpack_sbuffer_init(&buffer);
    msgpack_zone_init(&mempool, 8192);
    msgpack_packer_init(&loop_packer, &buffer, msgpack_sbuffer_write);

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct modify_rule, _head);

        msgpack_sbuffer_clear(&buffer);
        if (apply_modifying_rule(&loop_packer, &map, rule) !=
            FLB_FILTER_NOTOUCH) {

            msgpack_unpack(buffer.data, buffer.size, NULL, &mempool,
                           &deserialized);

            if (deserialized.type == MSGPACK_OBJECT_MAP) {
                map = deserialized;;
            }
            else {
                flb_error
                    ("[modify_filter] Expected MSGPACK_MAP, this is not a valid return value");
            }
        }
    }

    // * Record array init(2)
    msgpack_pack_array(packer, 2);

    // * * Record array item 1/2
    msgpack_pack_object(packer, ts);

    flb_debug
        ("[filter_modify] Input map size %d elements, output map size %d elements",
         records_in, map.via.map.size);

    // * * Record array item 2/2
    msgpack_pack_map(packer, map.via.map.size);
    map_pack_each(packer, &map);

    msgpack_sbuffer_destroy(&buffer);
    msgpack_zone_destroy(&mempool);

}

static inline bool evaluate_condition_KEY_EXISTS(msgpack_object * map,
                                                 struct modify_condition
                                                 *condition)
{
    return (map_count_keys_matching_str(map, condition->a, condition->a_len) >
            0);
}

static inline bool evaluate_condition_KEY_DOES_NOT_EXIST(msgpack_object * map,
                                                         struct
                                                         modify_condition
                                                         *condition)
{
    return !evaluate_condition_KEY_EXISTS(map, condition);
}

static int cb_modify_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config, void *data)
{
    struct filter_modify_ctx *ctx;

    // Create context
    ctx = flb_malloc(sizeof(struct filter_modify_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    mk_list_init(&ctx->rules);

    if (setup(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    // Set context
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_modify_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **out_buf, size_t * out_size,
                            struct flb_filter_instance *f_ins,
                            void *context, struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    struct filter_modify_ctx *ctx = context;

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // Records come in the format,
    //
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ],
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ]
    //
    // Example record,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            apply_modifying_rules(&packer, &result.data, ctx);
        }
        else {
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_modify_exit(void *data, struct flb_config *config)
{
    struct filter_modify_ctx *ctx = data;

    teardown(ctx);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_modify_plugin = {
    .name = "modify",
    .description = "modify events by specified field values",
    .cb_init = cb_modify_init,
    .cb_filter = cb_modify_filter,
    .cb_exit = cb_modify_exit,
    .flags = 0
};
