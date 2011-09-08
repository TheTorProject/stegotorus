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
test_s_x_http_transfer(void *state)
{
  struct proto_test_state *s = state;

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
    "Host: to-server\r\n"
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
  evbuffer_add(bufferevent_get_output(s->buf_client), msg1, 54);
  circuit_send(s->ckt_client);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_client)));
  tt_int_op(sizeof enc1-1, ==,
            evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_stn_op(enc1, ==, evbuffer_pullup(conn_get_inbound(s->conn_server),
                                      sizeof enc1-1),
            sizeof enc1-1);

  conn_recv(s->conn_server);
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_int_op(54, ==, evbuffer_get_length(bufferevent_get_input(s->buf_server)));
  tt_stn_op(msg1, ==,
            evbuffer_pullup(bufferevent_get_input(s->buf_server), 54), 54);

  /* client <- server */
  evbuffer_add(bufferevent_get_output(s->buf_server), msg2, 55);
  circuit_send(s->ckt_server);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_server)));
  tt_int_op(sizeof enc2-1, ==,
            evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_stn_op(enc2, ==, evbuffer_pullup(conn_get_inbound(s->conn_client),
                                      sizeof enc2-1),
            sizeof enc2-1);

  conn_recv(s->conn_client);
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_int_op(55, ==, evbuffer_get_length(bufferevent_get_input(s->buf_client)));
  tt_stn_op(msg2, ==,
            evbuffer_pullup(bufferevent_get_input(s->buf_client), 55), 55);

 end:;
}

static const char *const options_client[] =
  {"x_dsteg", "socks", "127.0.0.1:1800", "x_http"};

static const char *const options_server[] =
  {"x_dsteg", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

static const struct proto_test_args s_x_http_args =
  { ALEN(options_client), ALEN(options_server),
    options_client, options_server };

#define T(name) \
  { #name, test_s_x_http_##name, 0, NULL, NULL }

#define TF(name) \
  { #name, test_s_x_http_##name, 0, &proto_test_fixture, (void *)&s_x_http_args }

struct testcase_t s_x_http_tests[] = {
  TF(transfer),
  END_OF_TESTCASES
};
