/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "tinytest_macros.h"
#include "unittest.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

static void
test_dummy_option_parsing(void *unused)
{
  struct option_parsing_case {
    config_t *result;
    short should_succeed;
    short n_opts;
    const char *const opts[4];
  };
  static struct option_parsing_case cases[] = {
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

  /* Suppress logs for the duration of this function. */
  log_set_method(LOG_METHOD_NULL, NULL);

  struct option_parsing_case *c;
  for (c = cases; c->n_opts; c++) {
    c->result = config_create(c->n_opts, c->opts);
    if (c->should_succeed)
      tt_ptr_op(c->result, !=, NULL);
    else
      tt_ptr_op(c->result, ==, NULL);
  }

 end:
  for (c = cases; c->n_opts; c++)
    if (c->result)
      config_free(c->result);

  /* Unsuspend logging */
  log_set_method(LOG_METHOD_STDERR, NULL);
}

#define T(name) \
  { #name, test_dummy_##name, 0, NULL, NULL }

struct testcase_t dummy_tests[] = {
  T(option_parsing),
  END_OF_TESTCASES
};
