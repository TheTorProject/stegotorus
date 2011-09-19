/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef UNITTEST_H
#define UNITTEST_H

#include "tinytest_macros.h"

/* Test fixture shared by most protocol tests. */

struct proto_test_state
{
  struct event_base *base;
  struct bufferevent *buf_client;
  struct bufferevent *buf_server;

  config_t *cfg_client;
  config_t *cfg_server;

  circuit_t *ckt_client;
  circuit_t *ckt_server;

  conn_t *conn_client;
  conn_t *conn_server;

  const struct proto_test_args *args;
};

extern const struct testcase_setup_t proto_test_fixture;

/* Any test case that uses the above fixture must provide one of these
   as its setup_data. */
struct proto_test_args
{
  /* These fields are mandatory. */
  size_t nopts_client;
  size_t nopts_server;
  const char *const *opts_client;
  const char *const *opts_server;

  /* These fields are only used by "transfer" test cases and may be 0/NULL
     otherwise. */
  size_t len_c2s_on_wire;
  size_t len_s2c_on_wire;
  const char *c2s_on_wire;
  const char *s2c_on_wire;
};

#define ALEN(x) (sizeof x/sizeof x[0])

#endif
