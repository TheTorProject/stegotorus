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
      conn_close(s->conn_client);
  if (s->conn_server)
      conn_close(s->conn_server);

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

  struct bufferevent *pair[2];
  tt_assert(bufferevent_pair_new(s->base, 0, pair) == 0);
  tt_assert(pair[0]);
  tt_assert(pair[1]);
  bufferevent_enable(pair[0], EV_READ|EV_WRITE);
  bufferevent_enable(pair[1], EV_READ|EV_WRITE);

  s->conn_client = conn_create(s->cfg_client, pair[0], xstrdup("to-server"));
  tt_assert(s->conn_client);

  s->conn_server = conn_create(s->cfg_server, pair[1], xstrdup("to-client"));
  tt_assert(s->conn_server);

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

  /* Call the handshake method to satisfy the high-level contract,
     even though s_x_http doesn't use a handshake */
  tt_int_op(0, ==, conn_handshake(s->conn_client));

  /* That should have put nothing into the output buffer */
  tt_int_op(0, ==, evbuffer_get_length(conn_get_outbound(s->conn_client)));

  /* Ditto on the server side */
  tt_int_op(0, ==, conn_handshake(s->conn_server));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_outbound(s->conn_server)));

  static const char msg1[] =
    "this is a 54-byte message passed from client to server";
  static const char msg2[] =
    "this is a 55-byte message passed from server to client!";
  static const char enc1[] =
    "GET /7468697320697320612035342d62797465206d6573736167652070617373"
    "65642066726f6d20636c69656e7420746f20736572766572 HTTP/1.1\r\n"
    "Host: 127.0.0.1:1800\r\n"
    "Connection: close\r\n\r\n";
  static const char enc2[] =
    "HTTP/1.1 200 OK\r\n"
    "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: close\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Content-Length: 55\r\n\r\n"
    "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(s->scratch, msg1, 54);
  tt_int_op(0, ==, conn_send(s->conn_client, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(s->scratch));
  tt_int_op(sizeof enc1-1, ==,
            evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_stn_op(enc1, ==, evbuffer_pullup(conn_get_inbound(s->conn_server),
                                      sizeof enc1-1),
            sizeof enc1-1);

  tt_int_op(RECV_GOOD, ==, conn_recv(s->conn_server, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_int_op(54, ==, evbuffer_get_length(s->scratch));
  tt_stn_op(msg1, ==, evbuffer_pullup(s->scratch, 54), 54);

  /* empty scratch buffer before next test  */
  size_t buffer_len = evbuffer_get_length(s->scratch);
  tt_int_op(0, ==, evbuffer_drain(s->scratch, buffer_len));

  /* client <- server */
  evbuffer_add(s->scratch, msg2, 55);
  tt_int_op(0, ==, conn_send(s->conn_server, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(s->scratch));
  tt_int_op(sizeof enc2-1, ==,
            evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_stn_op(enc2, ==, evbuffer_pullup(conn_get_inbound(s->conn_client),
                                      sizeof enc2-1),
            sizeof enc2-1);

  tt_int_op(RECV_GOOD, ==, conn_recv(s->conn_client, s->scratch));
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_int_op(55, ==, evbuffer_get_length(s->scratch));
  tt_stn_op(msg2, ==, evbuffer_pullup(s->scratch, 55), 55);

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
