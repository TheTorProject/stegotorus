/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "tinytest_macros.h"

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

/* All the tests below use this test environment: */
struct test_dummy_state
{
  struct event_base *base;
  struct evbuffer *scratch;
  config_t *cfg_client;
  config_t *cfg_server;
  conn_t *conn_client;
  conn_t *conn_server;
};

static int
cleanup_dummy_state(const struct testcase_t *unused, void *state)
{
  struct test_dummy_state *s = (struct test_dummy_state *)state;

  if (s->conn_client)
      conn_free(s->conn_client);
  if (s->conn_server)
      conn_free(s->conn_server);

  if (s->cfg_client)
    config_free(s->cfg_client);
  if (s->cfg_server)
    config_free(s->cfg_server);

  if (s->scratch)
    evbuffer_free(s->scratch);
  if (s->base)
    event_base_free(s->base);

  free(state);
  return 1;
}

#define ALEN(x) (sizeof x/sizeof x[0])

static const char *const options_client[] =
  {"dummy", "socks", "127.0.0.1:1800"};

static const char *const options_server[] =
  {"dummy", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

static void *
setup_dummy_state(const struct testcase_t *unused)
{
  struct test_dummy_state *s = xzalloc(sizeof(struct test_dummy_state));

  s->base = event_base_new();
  tt_assert(s->base);

  s->scratch = evbuffer_new();
  tt_assert(s->scratch);

  s->cfg_client =
    config_create(ALEN(options_client), options_client);
  tt_assert(s->cfg_client);

  s->cfg_server =
    config_create(ALEN(options_server), options_server);
  tt_assert(s->cfg_server);

  s->conn_client = conn_create(s->cfg_client);
  tt_assert(s->conn_client);

  s->conn_server = conn_create(s->cfg_server);
  tt_assert(s->conn_server);

  struct bufferevent *pair[2];
  tt_assert(bufferevent_pair_new(s->base, 0, pair) == 0);
  tt_assert(pair[0]);
  tt_assert(pair[1]);
  bufferevent_enable(pair[0], EV_READ|EV_WRITE);
  bufferevent_enable(pair[1], EV_READ|EV_WRITE);

  s->conn_client->buffer = pair[0];
  s->conn_server->buffer = pair[1];

  return s;

 end:
  cleanup_dummy_state(NULL, s);
  return NULL;
}

static const struct testcase_setup_t dummy_fixture =
  { setup_dummy_state, cleanup_dummy_state };

static void
test_dummy_transfer(void *state)
{
  struct test_dummy_state *s = (struct test_dummy_state *)state;
  int n;
  struct evbuffer_iovec v[2];

  /* Call the handshake method to satisfy the high-level contract,
     even though dummy doesn't use a handshake */
  tt_int_op(0, ==, conn_handshake(s->conn_client));

  /* That should have put nothing into the output buffer */
  tt_int_op(0, ==, evbuffer_get_length(conn_get_outbound(s->conn_client)));

  /* Ditto on the server side */
  tt_int_op(0, ==, conn_handshake(s->conn_server));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_outbound(s->conn_server)));

  const char *msg1 = "this is a 54-byte message passed from client to server";
  const char *msg2 = "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(s->scratch, msg1, 54);
  tt_int_op(0, ==, conn_send(s->conn_client, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(s->scratch));
  tt_int_op(54, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  tt_int_op(RECV_GOOD, ==, conn_recv(s->conn_server, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  n = evbuffer_peek(s->scratch, -1, NULL, &v[0], 2);
  tt_int_op(1, ==, n); /* expect contiguous data */
  tt_stn_op(msg1, ==, v[0].iov_base, 54);

  /* empty scratch buffer before next test  */
  size_t buffer_len = evbuffer_get_length(s->scratch);
  tt_int_op(0, ==, evbuffer_drain(s->scratch, buffer_len));

  /* client <- server */
  evbuffer_add(s->scratch, msg2, 55);
  tt_int_op(0, ==, conn_send(s->conn_server, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(s->scratch));
  tt_int_op(55, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));

  tt_int_op(RECV_GOOD, ==, conn_recv(s->conn_client, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));

  n = evbuffer_peek(s->scratch, -1, NULL, &v[1], 2);
  tt_int_op(n, ==, 1); /* expect contiguous data */
  tt_stn_op(msg2, ==, v[1].iov_base, 55);

 end:;
}

#define T(name) \
  { #name, test_dummy_##name, 0, NULL, NULL }

#define TF(name) \
  { #name, test_dummy_##name, 0, &dummy_fixture, NULL }

struct testcase_t dummy_tests[] = {
  T(option_parsing),
  TF(transfer),
  END_OF_TESTCASES
};
