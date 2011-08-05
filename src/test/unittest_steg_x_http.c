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

/* All the tests below use this test environment: */
struct test_s_x_http_state
{
  struct event_base *base;
  struct evbuffer *scratch;
  config_t *cfg_client;
  config_t *cfg_server;
  conn_t *conn_client;
  conn_t *conn_server;
};

static int
cleanup_s_x_http_state(const struct testcase_t *unused, void *state)
{
  struct test_s_x_http_state *s = (struct test_s_x_http_state *)state;

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
  {"x_dsteg", "socks", "127.0.0.1:1800", "x_http"};

static const char *const options_server[] =
  {"x_dsteg", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

static void *
setup_s_x_http_state(const struct testcase_t *unused)
{
  struct test_s_x_http_state *s = xzalloc(sizeof(struct test_s_x_http_state));

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
  s->conn_client->peername = xstrdup("127.0.0.1:1800");
  s->conn_server->peername = xstrdup("127.0.0.1:1799");

  return s;

 end:
  cleanup_s_x_http_state(NULL, s);
  return NULL;
}

static const struct testcase_setup_t s_x_http_fixture =
  { setup_s_x_http_state, cleanup_s_x_http_state };

static void
test_s_x_http_transfer(void *state)
{
  struct test_s_x_http_state *s = (struct test_s_x_http_state *)state;
  int n;
  struct evbuffer_iovec v[2];

  /* Call the handshake method to satisfy the high-level contract,
     even though s_x_http doesn't use a handshake */
  tt_int_op(0, ==, proto_handshake(s->conn_client));

  /* That should have put nothing into the output buffer */
  tt_int_op(0, ==, evbuffer_get_length(conn_get_outbound(s->conn_client)));

  /* Ditto on the server side */
  tt_int_op(0, ==, proto_handshake(s->conn_server));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_outbound(s->conn_server)));

  const char *msg1 = "this is a 54-byte message passed from client to server";
  const char *msg2 = "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(s->scratch, msg1, 54);
  tt_int_op(0, ==, proto_send(s->conn_client, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(s->scratch));
  tt_int_op(167, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  tt_int_op(RECV_GOOD, ==, proto_recv(s->conn_server, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  n = evbuffer_peek(s->scratch, -1, NULL, &v[0], 2);
  tt_int_op(1, ==, n); /* expect contiguous data */
  tt_stn_op(msg1, ==, v[0].iov_base, 54);

  /* empty scratch buffer before next test  */
  size_t buffer_len = evbuffer_get_length(s->scratch);
  tt_int_op(0, ==, evbuffer_drain(s->scratch, buffer_len));

  /* client <- server */
  evbuffer_add(s->scratch, msg2, 55);
  tt_int_op(0, ==, proto_send(s->conn_server, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(s->scratch));
  tt_int_op(218, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));

  tt_int_op(RECV_GOOD, ==, proto_recv(s->conn_client, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));

  n = evbuffer_peek(s->scratch, -1, NULL, &v[1], 2);
  tt_int_op(n, ==, 1); /* expect contiguous data */
  tt_stn_op(msg2, ==, v[1].iov_base, 55);

 end:;
}

#define T(name) \
  { #name, test_s_x_http_##name, 0, NULL, NULL }

#define TF(name) \
  { #name, test_s_x_http_##name, 0, &s_x_http_fixture, NULL }

struct testcase_t s_x_http_tests[] = {
  TF(transfer),
  END_OF_TESTCASES
};
