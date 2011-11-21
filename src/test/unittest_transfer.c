/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "unittest.h"
#include "connections.h"

#include <event2/buffer.h>

static const char msg1[] =
  "this is a 54-byte message passed from client to server";
static const char msg2[] =
  "this is a 55-byte message passed from server to client!";

#define SLEN(s) (sizeof(s)-1)

static void
test_transfer(void *state)
{
  struct proto_test_state *s = state;
  const struct proto_test_args *a = s->args;

  /* Handshake */
  tt_int_op(0, ==, conn_handshake(s->conn_client));
  tt_int_op(0, ==, conn_recv(s->conn_server));
  tt_int_op(0, ==, conn_handshake(s->conn_server));
  tt_int_op(0, ==, conn_recv(s->conn_client));
  /* End of Handshake */

  /* client -> server */
  evbuffer_add(bufferevent_get_output(s->buf_client), msg1, SLEN(msg1));
  circuit_send(s->ckt_client);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_client)));
  tt_int_op(a->len_c2s_on_wire, ==,
            evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_mem_op(a->c2s_on_wire, ==,
            evbuffer_pullup(conn_get_inbound(s->conn_server),
                            a->len_c2s_on_wire),
            a->len_c2s_on_wire);

  conn_recv(s->conn_server);
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_server)));
  tt_int_op(SLEN(msg1), ==,
            evbuffer_get_length(bufferevent_get_input(s->buf_server)));
  tt_mem_op(msg1, ==,
            evbuffer_pullup(bufferevent_get_input(s->buf_server), SLEN(msg1)),
            SLEN(msg1));

  /* server -> client */
  evbuffer_add(bufferevent_get_output(s->buf_server), msg2, SLEN(msg2));
  circuit_send(s->ckt_server);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_server)));
  tt_int_op(a->len_s2c_on_wire, ==,
            evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_mem_op(a->s2c_on_wire, ==,
            evbuffer_pullup(conn_get_inbound(s->conn_client),
                            a->len_s2c_on_wire),
            a->len_s2c_on_wire);

  conn_recv(s->conn_client);
  tt_int_op(0, ==, evbuffer_get_length(conn_get_inbound(s->conn_client)));
  tt_int_op(SLEN(msg2), ==,
            evbuffer_get_length(bufferevent_get_input(s->buf_client)));
  tt_mem_op(msg2, ==,
            evbuffer_pullup(bufferevent_get_input(s->buf_client), SLEN(msg2)),
            SLEN(msg2));

 end:;
}

#define enc1_dummy msg1
#define enc2_dummy msg2

#if 0 /* temporarily disabled - causes crashes */
static const char enc1_s_x_http[] =
    "GET /003600007468697320697320612035342d62797465206d6573736167652070617"
    "37365642066726f6d20636c69656e7420746f2073657276657200== HTTP/1.1\r\n"
    "Host: to-server\r\n"
    "Connection: close\r\n\r\n";
static const char enc2_s_x_http[] =
    "HTTP/1.1 200 OK\r\n"
    "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: close\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Content-Length: 60\r\n\r\n"
    "\x00\x37\x00\x00"
    "this is a 55-byte message passed from server to client!\x00";
#endif

static const char *const o_client_dummy[] =
  {"dummy", "socks", "127.0.0.1:1800"};

static const char *const o_server_dummy[] =
  {"dummy", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

#if 0 /* temporarily disabled - causes crashes */
static const char *const o_client_s_x_http[] =
  {"x_dsteg", "socks", "127.0.0.1:1800", "x_http"};

static const char *const o_server_s_x_http[] =
  {"x_dsteg", "server", "127.0.0.1:1800", "127.0.0.1:1801"};
#endif

#define TA(name)                                                \
  static const struct proto_test_args tr_##name##_args =        \
    { ALEN(o_client_##name), ALEN(o_server_##name),             \
      o_client_##name, o_server_##name,                         \
      SLEN(enc1_##name), SLEN(enc2_##name),                     \
      enc1_##name, enc2_##name }

TA(dummy);
#if 0
TA(s_x_http);
#endif

#define T(name) \
  { #name, test_transfer, 0, &proto_test_fixture, (void *)&tr_##name##_args }

struct testcase_t transfer_tests[] = {
  T(dummy),
#if 0
  T(s_x_http),
#endif
  END_OF_TESTCASES
};
