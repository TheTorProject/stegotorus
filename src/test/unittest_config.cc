/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "unittest.h"

#include "protocol.h"

struct option_parsing_case {
  config_t *result;
  short should_succeed;
  short n_opts;
  const char *const opts[6];
};

static void
test_config(void *cases)
{
  struct option_parsing_case *c;
  for (c = (struct option_parsing_case *)cases; c->n_opts; c++) {
    c->result = config_create(c->n_opts, c->opts);
    if (c->should_succeed)
      tt_ptr_op(c->result, !=, NULL);
    else
      tt_ptr_op(c->result, ==, NULL);
  }
 end:;
}

static void *
setup_test_config(const struct testcase_t *tc)
{
  /* Suppress logs for the duration of this test. */
  log_set_method(LOG_METHOD_NULL, NULL);

  /* Forward the test data to the actual test function. */
  return tc->setup_data;
}

static int
cleanup_test_config(const struct testcase_t *, void *state)
{
  struct option_parsing_case *c;
  for (c = (struct option_parsing_case *)state; c->n_opts; c++)
    if (c->result)
      config_free(c->result);

  /* Reactivate logging */
  log_set_method(LOG_METHOD_STDERR, NULL);
  return 1;
}

static const struct testcase_setup_t config_fixture =
  { setup_test_config, cleanup_test_config };

static struct option_parsing_case oc_x_null[] = {
  /* wrong number of options */
  { 0, 0, 1, {"x_null"} },
  { 0, 0, 2, {"x_null", "client"} },
  { 0, 0, 3, {"x_null", "client", "127.0.0.1:5552"} },
  { 0, 0, 3, {"x_null", "server", "127.0.0.1:5552"} },
  { 0, 0, 4, {"x_null", "socks", "127.0.0.1:5552", "192.168.1.99:11253"} },
  /* unrecognized mode */
  { 0, 0, 3, {"x_null", "floodcontrol", "127.0.0.1:5552" } },
  { 0, 0, 4, {"x_null", "--frobozz", "client", "127.0.0.1:5552"} },
  { 0, 0, 4, {"x_null", "client", "--frobozz", "127.0.0.1:5552"} },
  /* bad address */
  { 0, 0, 3, {"x_null", "socks", "@:5552"} },
  { 0, 0, 3, {"x_null", "socks", "127.0.0.1:notanumber"} },
  /* should succeed */
  { 0, 1, 4, {"x_null", "client", "127.0.0.1:5552", "192.168.1.99:11253" } },
  { 0, 1, 4, {"x_null", "client", "127.0.0.1", "192.168.1.99:11253" } },
  { 0, 1, 4, {"x_null", "server", "127.0.0.1:5552", "192.168.1.99:11253" } },
  { 0, 1, 3, {"x_null", "socks", "127.0.0.1:5552" } },

  { 0, 0, 0, {0} }
};

#define T(name) \
  { #name, test_config, 0, &config_fixture, oc_##name }

struct testcase_t config_tests[] = {
  T(x_null),
  END_OF_TESTCASES
};
