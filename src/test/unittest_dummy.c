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

static void
test_dummy_transfer(void *state)
{
  struct proto_test_state *s = state;

  /* Call the handshake method to satisfy the high-level contract,
     even though dummy doesn't use a handshake */
  tt_int_op(0, ==, conn_handshake(s->conn_client));

  /* That should have put nothing into the output buffer */
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  /* Ditto on the server side */
  tt_int_op(0, ==, conn_handshake(s->conn_server));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));

  const char *msg1 = "this is a 54-byte message passed from client to server";
  const char *msg2 = "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(bufferevent_get_output(s->buf_client), msg1, 54);
  circuit_send(s->ckt_client);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_client)));
  tt_int_op(54, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  conn_recv(s->conn_server);
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_int_op(54, ==, evbuffer_get_length(bufferevent_get_input(s->buf_server)));
  tt_stn_op(msg1, ==,
            evbuffer_pullup(bufferevent_get_input(s->buf_server), 54), 54);

  /* client <- server */
  evbuffer_add(bufferevent_get_output(s->buf_server), msg2, 55);
  circuit_send(s->ckt_server);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_server)));
  tt_int_op(55, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));

  conn_recv(s->conn_client);
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_int_op(55, ==, evbuffer_get_length(bufferevent_get_input(s->buf_client)));
  tt_stn_op(msg2, ==,
            evbuffer_pullup(bufferevent_get_input(s->buf_client), 55), 55);

 end:;
}

static const char *const options_client[] =
  {"dummy", "socks", "127.0.0.1:1800"};

static const char *const options_server[] =
  {"dummy", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

static const struct proto_test_args dummy_args =
  { ALEN(options_client), ALEN(options_server),
    options_client, options_server };

#define T(name) \
  { #name, test_dummy_##name, 0, NULL, NULL }

#define TF(name) \
  { #name, test_dummy_##name, 0, &proto_test_fixture, (void *)&dummy_args }

struct testcase_t dummy_tests[] = {
  T(option_parsing),
  TF(transfer),
  END_OF_TESTCASES
};
