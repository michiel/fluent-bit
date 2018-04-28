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

static void helper_pack_string(msgpack_packer * packer, const char *str, int len)
{
    if (str == NULL) {
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
                ("[filter_modify] invalid value, expected key and value");
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
        else if (strcasecmp(prop->key, "hardrename") == 0) {
          rule->ruletype = HARDRENAME;
        }
        else if (strcasecmp(prop->key, "add_if_not_present") == 0) {
          rule->ruletype = ADD;
        }
        else if (strcasecmp(prop->key, "add") == 0) {
          rule->ruletype = ADD;
        }
        else if (strcasecmp(prop->key, "set") == 0) {
          rule->ruletype = SET;
        }
        else if (strcasecmp(prop->key, "copy") == 0) {
          rule->ruletype = COPY;
        }
        else if (strcasecmp(prop->key, "hardcopy") == 0) {
          rule->ruletype = HARDCOPY;
        }
        else {
            teardown(ctx);
            flb_free(rule);
            return -1;
        }

				mk_list_add(&rule->_head, &ctx->rules);
				ctx->rules_cnt++;

    }

    return 0;
}

static inline bool is_true(msgpack_object_kv * kv,
                                  struct modify_rule *rule)
{
  return true;
}

static inline bool kv_key_matches_rule_key(msgpack_object_kv * kv,
                                  struct modify_rule *rule)
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
        return false;
    }

    return ((rule->key_len == klen) && (strncmp(rule->key, key, klen) == 0)
        );
}

static inline bool not_kv_key_matches_rule_key(msgpack_object_kv * kv,
                                      struct modify_rule *rule)
{
    return !kv_key_matches_rule_key(kv, rule);
}

static inline bool kv_key_matches_rule_val(msgpack_object_kv * kv,
                                  struct modify_rule *rule)
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
        return false;
    }

    return ((rule->val_len == klen) && (strncmp(rule->val, key, klen) == 0)
        );
}

static inline bool not_kv_key_matches_rule_val(msgpack_object_kv * kv,
                                      struct modify_rule *rule)
{
    return !kv_key_matches_rule_val(kv, rule);
}

static inline int map_count_keys_matching_rule(msgpack_object * map,
                                                  struct modify_rule *rule)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (kv_key_matches_rule_key(&map->via.map.ptr[i], rule)) {
            count++;
        }
    }
    return count;
}

static inline void map_pack_each_fn(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct filter_modify_rule *rule,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_modify_ctx * ctx)
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
                               struct filter_modify_ctx *ctx,
                               bool(*f) (msgpack_object_kv * kv,
                                         struct filter_modify_ctx * ctx)
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

static inline void apply_rule_RENAME(msgpack_packer * packer,
                                        msgpack_object * map,
                                        struct modify_rule *rule)
{
    int i;
    bool matched;

    for (i = 0; i < map->via.map.size; i++) {

        if (kv_key_matches_rule_key(&map->via.map.ptr[i], rule)) {
          helper_pack_string(packer, matched_rule->val, matched_rule->val_len);
          matched = true;
        }
        else {
          msgpack_pack_object(packer, map->via.map.ptr[i].key);
        }

        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }

    if (!matched) {
      flb_warn("[filter_modify] Rule RENAME %s : this key does not exist. No change to this record", rule->key);
    }
}

static inline void apply_rule_HARDRENAME(msgpack_packer * packer,
                                        msgpack_object * map,
                                        struct modify_rule *rule)
{
    int i;
    bool matched;

    for (i = 0; i < map->via.map.size; i++) {

        if (kv_key_matches_rule_key(&map->via.map.ptr[i], rule)) {
          helper_pack_string(packer, matched_rule->val, matched_rule->val_len);
          matched = true;
        }
        else {
          msgpack_pack_object(packer, map->via.map.ptr[i].key);
        }

        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }

    if (!matched) {
      flb_warn("[filter_modify] Rule RENAME %s : this key does not exist. No change to this record", rule->key);
    }
}

static inline void apply_rule_ADD(msgpack_packer * packer,
    msgpack_object * map,
    struct modify_rule *rule)
{
    map_pack_each_fn(packer, map, rule, is_true);
    if (map_count_keys_matching_rule(rule) == 0) {
        helper_pack_string(packer, rule->key, matched_rule->key_len);
        helper_pack_string(packer, rule->val, matched_rule->val_len);
    }
    else {
      flb_warn("[filter_modify] Rule ADD %s : this key already exists, skipping", rule->key);
    }
}

static inline void apply_rule_SET(msgpack_packer * packer,
    msgpack_object * map,
    struct modify_rule *rule)
{
    map_pack_each_fn(packer, map, rule, not_kv_key_matches_rule_key);
    helper_pack_string(packer, rule->key, matched_rule->key_len);
    helper_pack_string(packer, rule->val, matched_rule->val_len);
}

static inline void apply_rule_REMOVE(msgpack_packer * packer,
    msgpack_object * map,
    struct modify_rule *rule)
{
    map_pack_each_fn(packer, map, rule, not_kv_key_matches_rule_key);
}

static inline void apply_modifying_rule(msgpack_packer * packer,
    msgpack_object * root,
    struct modify_rule * rule
    )
{
  switch (rule->type) {
    case ADD:
      apply_rule_ADD(packer, map, rule);
      break;
    case SET:
      apply_rule_SET(packer, map, rule);
      break;
    case RENAME:
      apply_rule_RENAME(packer, map, rule);
      break;
    case REMOVE:
      apply_rule_REMOVE(packer, map, rule);
      break;
  }

}

static inline void apply_modifying_rules(msgpack_packer * packer,
                                         msgpack_object * root,
                                         struct filter_modify_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];
    struct modify_rule *rule;


    msgpack_sbuffer in_buffer;
    msgpack_sbuffer_init(&in_buffer);

    msgpack_packer in_packer;
    msgpack_packer_init(&in_packer, &in_buffer, msgpack_sbuffer_write);

		mk_list_foreach_safe(head, tmp, &ctx->rules) {
			rule = mk_list_entry(head, struct modify_rule, _head);
      apply_modifying_rule(packer, XXX, rule);

		}

    int records_in = map.via.map.size;

    // * Record array init(2)
    msgpack_pack_array(packer, 2);

    // * * Record array item 1/2
    msgpack_pack_object(packer, ts);

    flb_debug
        ("[filter_modify] Input map size %d elements, output map size %d elements",
         records_in, map.via.map.size);

    // * * Record array item 2/2
    msgpack_pack_map(packer, map.via.map.size);
    pack_map(packer, &map);

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
