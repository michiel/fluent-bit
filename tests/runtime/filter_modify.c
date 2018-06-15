/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;

/* Test data */

/* Test functions */
void flb_test_filter_modify_hammer(void);

/* Test list */
TEST_LIST = {
    {"hammer", flb_test_filter_modify_hammer },
    {NULL, NULL}
};


void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    output = val;
    pthread_mutex_unlock(&result_mutex);
}

char *get_output(void)
{
    char *val;

    pthread_mutex_lock(&result_mutex);
    val = output;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

int callback_test(void* record, size_t size, void* data)
{
    if (size > 0) {
        flb_error("[test_filter_parser] received record: '%s' with len %s - ", record, size);
        flb_error("[test_filter_parser] received data: %s", data);
        set_output(record); /* success */
        return 0;
    } else {
        flb_debug("[test_filter_parser] No data received");
        set_output(NULL); /* fail */
        return 1;
    }
}

void flb_test_filter_modify_hammer(void)
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    // out_ffd = flb_output(ctx, (char *) "stdout", &cb);
    // out_ffd = flb_output(ctx, (char *) "lib", (void*)callback_test);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    filter_ffd = flb_filter(ctx, (char *) "modify", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
        "Match", "*",
        "Rename", "wills wood",
        "Set", "wokka williamson",
        "Hard_Rename", "witchetty wokka",
        "Hard_Rename", "wokka wood",
        "Hard_Rename", "witchetty wills",
        "Rename", "wollongong wingman",
        "Rename", "wobbegong wombat",
        "Set", "wongawonga wingman",
        "Rename", "wag wombat",
        "Rename", "witchetty wag",
        "Set", "wobble wag",
        "Rename", "willywilly wirrah",
        "Hard_Rename", "wills wokka",
        "Hard_Rename", "williamson wombat",
        "Set", "wood willywilly",
        "Hard_Rename", "wombat wollongong",
        "Set", "wills wipe",
        "Hard_Rename", "wirrah wag",
        "Set", "wobbegong wood",
        "Rename", "willy witchetty",
        "Rename", "wingman wombat",
        "Set", "willy wombat",
        "Hard_Rename", "wood wag",
        "Set", "wills wobble",
        "Rename", "wobble wingman",
        "Rename", "wills wobbegong",
        "Set", "wingman wokka",
        NULL);

    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(5); /* waiting flush */

    output = get_output();
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "\"tonest\":\"{\"to_nest\":\"This is the data to nest\"}\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}

