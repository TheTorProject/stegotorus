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
  tt_int_op(RECV_BAD, !=, conn_recv_raw(s->conn_server));
  tt_int_op(0, ==, conn_handshake(s->conn_server));
  tt_int_op(RECV_BAD, !=, conn_recv_raw(s->conn_client));
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

static const char enc1_obfs2[] =
  "\x48\x63\x37\x28\xbf\x68\xd4\x7c\x86\x59\x89\x71\x19\x88\x47\x07\xb1\x75"
  "\xb3\x85\x55\x1a\x02\x4b\x76\xa2\x4e\x88\x04\x4e\xa4\x4a\xaf\x61\x84\x23"
  "\xd6\x95\x44\xfe\x3a\x5b\x5b\x72\x09\xf7\x3c\xcc\xb1\xfc\x68\xd5\x57\x90";
static const char enc2_obfs2[] =
  "\x6c\xe0\xe3\xb5\x49\x9e\x3e\x0e\x1d\xea\x04\x4d\x69\xf8\x1f\x30\x53\x7f"
  "\xfd\x36\xaa\x77\x17\xb4\x69\x2b\x7b\x68\x34\x98\xaa\x7f\x7f\xc7\xdc\x6a"
  "\x91\x58\x00\xc5\x2f\xf9\x30\xd4\x82\x48\xc3\xb6\xda\x51\xf0\x2f\xe0\x7e"
  "\x6d";

static const char enc1_s_x_http[] =
    "GET /7468697320697320612035342d62797465206d6573736167652070617373"
    "65642066726f6d20636c69656e7420746f20736572766572 HTTP/1.1\r\n"
    "Host: to-server\r\n"
    "Connection: close\r\n\r\n";
static const char enc2_s_x_http[] =
    "HTTP/1.1 200 OK\r\n"
    "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: close\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Content-Length: 55\r\n\r\n"
    "this is a 55-byte message passed from server to client!";

static const char *const o_client_dummy[] =
  {"dummy", "socks", "127.0.0.1:1800"};

static const char *const o_server_dummy[] =
  {"dummy", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

static const char *const o_client_obfs2[] =
  {"obfs2", "--shared-secret=hahaha", "socks", "127.0.0.1:1800"};

static const char *const o_server_obfs2[] =
  {"obfs2", "--shared-secret=hahaha",
   "--dest=127.0.0.1:1500", "server", "127.0.0.1:1800"};

static const char *const o_client_s_x_http[] =
  {"x_dsteg", "socks", "127.0.0.1:1800", "x_http"};

static const char *const o_server_s_x_http[] =
  {"x_dsteg", "server", "127.0.0.1:1800", "127.0.0.1:1801"};

#define TA(name)                                                \
  static const struct proto_test_args tr_##name##_args =        \
    { ALEN(o_client_##name), ALEN(o_server_##name),             \
      o_client_##name, o_server_##name,                         \
      SLEN(enc1_##name), SLEN(enc2_##name),                     \
      enc1_##name, enc2_##name }

TA(dummy);
TA(obfs2);
TA(s_x_http);

#define T(name) \
  { #name, test_transfer, 0, &proto_test_fixture, (void *)&tr_##name##_args }

struct testcase_t transfer_tests[] = {
  T(dummy),
  T(obfs2),
  T(s_x_http),
  END_OF_TESTCASES
};
