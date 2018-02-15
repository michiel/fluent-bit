/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;

/* Test data */

/* Test functions */
void flb_test_filter_nest_static(void);

/* Test list */
TEST_LIST = {
    {"static_single", flb_test_filter_nest_static },
    {"star_single", flb_test_filter_nest_star_single },
    {"star_multiple", flb_test_filter_nest_star_multiple },
    {"none", flb_test_filter_nest_none },
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

void flb_test_filter_nest_static(void)
{
    int i;
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    filter_ffd = flb_filter(ctx, (char *) "nest", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
        "Match", "*",
        "Wildcard", "to_nest",
        "Nest_under", "nested_key",
        NULL);

    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"to_nest\":\"This is the data to nest\", \"extra\":\"Some more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */

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


void flb_test_filter_nest_star_single(void)
{
    int i;
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    filter_ffd = flb_filter(ctx, (char *) "nest", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
        "Match", "*",
        "Wildcard", "to_nest_*",
        "Nest_under", "nested_key",
        NULL);

    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"do_not_nest\":\"Do not nest\", \"to_nest_1\":\"Nest this\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */

    output = get_output();
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "{\"do_not_nest\":\"Do not nest\", \"nested_key\":{\"to_nest_1\":\"Nest this\"}}";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_filter_nest_star_multiple(void)
{
    int i;
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    filter_ffd = flb_filter(ctx, (char *) "nest", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
        "Match", "*",
        "Wildcard", "to_nest_*",
        "Nest_under", "nested_key",
        NULL);

    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"do_not_nest\":\"Do not nest\", \"to_nest_1\":\"Nest this\", \"to_nest_2\":\"Also nest this.\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */

    output = get_output();
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "{\"do_not_nest\":\"Do not nest\", \"nested_key\":{\"to_nest_1\":\"Nest this\", \"to_nest_2\":\"Also nest this.\"}}";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_nest_none(void)
{
    int i;
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    filter_ffd = flb_filter(ctx, (char *) "nest", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
        "Match", "*",
        "Wildcard", "to_nest_*",
        "Nest_under", "nested_key",
        NULL);

    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"do_not_nest\":\"Do not nest\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */

    output = get_output();
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "{\"do_not_nest\":\"Do not nest\", \"nested_key\":{}}";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}

