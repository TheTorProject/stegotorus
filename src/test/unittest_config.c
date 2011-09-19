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
  for (c = cases; c->n_opts; c++) {
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
cleanup_test_config(const struct testcase_t *tc, void *state)
{
  struct option_parsing_case *c;
  for (c = state; c->n_opts; c++)
    if (c->result)
      config_free(c->result);

  /* Reactivate logging */
  log_set_method(LOG_METHOD_STDERR, NULL);
  return 1;
}

static const struct testcase_setup_t config_fixture =
  { setup_test_config, cleanup_test_config };

static struct option_parsing_case oc_dummy[] = {
  /* wrong number of options */
  { 0, 0, 1, {"dummy"} },
  { 0, 0, 2, {"dummy", "client"} },
  { 0, 0, 3, {"dummy", "client", "127.0.0.1:5552"} },
  { 0, 0, 3, {"dummy", "server", "127.0.0.1:5552"} },
  { 0, 0, 4, {"dummy", "socks", "127.0.0.1:5552", "192.168.1.99:11253"} },
  /* unrecognized mode */
  { 0, 0, 3, {"dummy", "floodcontrol", "127.0.0.1:5552" } },
  { 0, 0, 4, {"dummy", "--frobozz", "client", "127.0.0.1:5552"} },
  { 0, 0, 4, {"dummy", "client", "--frobozz", "127.0.0.1:5552"} },
  /* bad address */
  { 0, 0, 3, {"dummy", "socks", "@:5552"} },
  { 0, 0, 3, {"dummy", "socks", "127.0.0.1:notanumber"} },
  /* should succeed */
  { 0, 1, 4, {"dummy", "client", "127.0.0.1:5552", "192.168.1.99:11253" } },
  { 0, 1, 4, {"dummy", "client", "127.0.0.1", "192.168.1.99:11253" } },
  { 0, 1, 4, {"dummy", "server", "127.0.0.1:5552", "192.168.1.99:11253" } },
  { 0, 1, 3, {"dummy", "socks", "127.0.0.1:5552" } },

  { 0, 0, 0, {0} }
};

static struct option_parsing_case oc_obfs2[] = {
  /** good option list */
  { 0, 1, 4, {"obfs2", "--shared-secret=a", "socks", "127.0.0.1:0"} },
  /** two --dest. */
  { 0, 0, 5, {"obfs2", "--dest=127.0.0.1:5555", "--dest=a",
              "server", "127.0.0.1:5552"} },
  /** unknown arg */
  { 0, 0, 4, {"obfs2", "--gabura=a", "server", "127.0.0.1:5552"} },
  /** too many args */
  { 0, 0, 6, {"obfs2", "1", "2", "3", "4", "5" } },
  /** wrong mode  */
  { 0, 0, 4, {"obfs2", "--dest=1:1", "gladiator", "127.0.0.1:5552"} },
  /** bad listen addr */
  { 0, 0, 4, {"obfs2", "--dest=1:1", "server", "127.0.0.1:a"} },
  /** bad dest addr */
  { 0, 0, 4, {"obfs2", "--dest=1:b", "server", "127.0.0.1:1"} },
  /** socks with dest */
  { 0, 0, 4, {"obfs2", "--dest=1:2", "socks", "127.0.0.1:1"} },
  /** server without dest */
  { 0, 0, 4, {"obfs2", "--shared-secret=a", "server", "127.0.0.1:1"} },

  { 0, 0, 0, {0} }
};

static struct option_parsing_case oc_s_x_http[] = {
  /* good */
  { 0, 1, 4, {"x_dsteg", "socks", "127.0.0.1:1800", "x_http"} },
  { 0, 1, 4, {"x_dsteg", "server", "127.0.0.1:1800", "127.0.0.1:1801"} },
  { 0, 1, 5, {"x_dsteg", "client", "127.0.0.1:1800", "127.0.0.1:1801","x_http"}},
  /* wrong number of options */
  { 0, 0, 1, {"x_dsteg"} },
  { 0, 0, 2, {"x_dsteg", "client"} },
  { 0, 0, 3, {"x_dsteg", "client", "127.0.0.1:5552"} },
  { 0, 0, 4, {"x_dsteg", "client", "127.0.0.1:5552", "192.168.1.99:11253" } },
  { 0, 0, 3, {"x_dsteg", "socks", "127.0.0.1:5552" } },
  /* unrecognized mode */
  { 0, 0, 3, {"x_dsteg", "floodcontrol", "127.0.0.1:5552" } },
  { 0, 0, 4, {"x_dsteg", "--frobozz", "client", "127.0.0.1:5552"} },
  { 0, 0, 4, {"x_dsteg", "client", "--frobozz", "127.0.0.1:5552"} },

  { 0, 0, 0, {0} }
};

#define T(name) \
  { #name, test_config, 0, &config_fixture, oc_##name }

struct testcase_t config_tests[] = {
  T(dummy),
  T(obfs2),
  T(s_x_http),
  END_OF_TESTCASES
};
