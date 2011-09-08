/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef UNITTEST_H
#define UNITTEST_H

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
};

extern const struct testcase_setup_t proto_test_fixture;

/* Any test case that uses the above fixture must provide one of these
   as its setup_data. */
struct proto_test_args
{
  size_t nopts_client;
  size_t nopts_server;
  const char *const *opts_client;
  const char *const *opts_server;
};

#define ALEN(x) (sizeof x/sizeof x[0])

#endif
