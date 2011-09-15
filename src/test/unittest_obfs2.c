/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "tinytest_macros.h"
#include "unittest.h"

#define PROTOCOL_OBFS2_PRIVATE
#define CRYPT_PRIVATE
#include "protocols/obfs2.h"
#include "crypt.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

PROTO_CAST_HELPERS(obfs2)

static void
test_obfs2_handshake(void *state)
{
  struct proto_test_state *s = state;
  obfs2_conn_t *client_state = downcast_conn(s->conn_client);
  obfs2_conn_t *server_state = downcast_conn(s->conn_server);

  /* We create a client handshake message */
  tt_int_op(0, <=, conn_handshake(s->conn_client));

  /* That should have put something into the output buffer */
  tt_int_op(0, <, evbuffer_get_length(conn_get_inbound(s->conn_server)));

  /* Simulate the server receiving and processing the client's
     handshake message */
  conn_recv(s->conn_server);

  /* That should have put nothing into the upstream buffer */
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_server)));

  /* Same for server to client */
  tt_int_op(0, <=, conn_handshake(s->conn_server));
  tt_int_op(0, <, evbuffer_get_length(conn_get_inbound(s->conn_client)));
  conn_recv(s->conn_client);
  tt_int_op(0, ==, evbuffer_get_length(bufferevent_get_output(s->buf_client)));

  /* The handshake is now complete. We should have:
     client's send_crypto == server's recv_crypto
     server's send_crypto == client's recv_crypto . */
  tt_mem_op(client_state->send_crypto, ==, server_state->recv_crypto,
            sizeof(crypt_t));

  tt_mem_op(client_state->recv_crypto, ==, server_state->send_crypto,
            sizeof(crypt_t));

 end:;
}

/* We are going to split client's handshake into:
   msgclient_1 = [OBFUSCATE_SEED_LENGTH + 8 + <one fourth of padding>]
   and msgclient_2 = [<rest of padding>].

   We are then going to split server's handshake into:
   msgserver_1 = [OBFUSCATE_SEED_LENGTH + 8]
   and msgserver_2 = [<all padding>].

   Afterwards we will verify that they both got the correct keys.
   That's right, this unit test is loco . */
static void
test_obfs2_split_handshake(void *state)
{
  struct proto_test_state *s = state;
  obfs2_conn_t *client_state = downcast_conn(s->conn_client);
  obfs2_conn_t *server_state = downcast_conn(s->conn_server);

  uint32_t magic = htonl(OBFUSCATE_MAGIC_VALUE);
  uint32_t plength1, plength1_msg1, plength1_msg2, send_plength1;
  const uchar *seed1;

  /* generate padlen */
  tt_int_op(0, <=, random_bytes((uchar*)&plength1, 4));

  plength1 %= OBFUSCATE_MAX_PADDING;

  plength1_msg1 = plength1 / 4;
  plength1_msg2 = plength1 - plength1_msg1;

  send_plength1 = htonl(plength1);

  uchar msgclient_1[OBFUSCATE_MAX_PADDING + OBFUSCATE_SEED_LENGTH + 8];
  uchar msgclient_2[OBFUSCATE_MAX_PADDING];

  seed1 = client_state->initiator_seed;

  memcpy(msgclient_1, seed1, OBFUSCATE_SEED_LENGTH);
  memcpy(msgclient_1+OBFUSCATE_SEED_LENGTH, &magic, 4);
  memcpy(msgclient_1+OBFUSCATE_SEED_LENGTH+4, &send_plength1, 4);
  tt_int_op(0, <=, random_bytes(msgclient_1+OBFUSCATE_SEED_LENGTH+8,
                                plength1_msg1));

  stream_crypt(client_state->send_padding_crypto,
               msgclient_1+OBFUSCATE_SEED_LENGTH, 8+plength1_msg1);

  /* Client sends handshake part 1 */
  evbuffer_add(conn_get_outbound(s->conn_client), msgclient_1,
               OBFUSCATE_SEED_LENGTH+8+plength1_msg1);

  /* Server receives handshake part 1 */
  conn_recv(s->conn_server);
  tt_int_op(ST_WAIT_FOR_PADDING, ==, server_state->state);

  /* Preparing client's handshake part 2 */
  tt_int_op(0, <=, random_bytes(msgclient_2, plength1_msg2));
  stream_crypt(client_state->send_padding_crypto, msgclient_2, plength1_msg2);

  /* Client sends handshake part 2 */
  evbuffer_add(conn_get_outbound(s->conn_client), msgclient_2, plength1_msg2);

  /* Server receives handshake part 2 */
  conn_recv(s->conn_server);
  tt_int_op(ST_OPEN, ==, server_state->state);

  /* Since everything went right, let's do a server to client handshake now! */
  uint32_t plength2, send_plength2;
  const uchar *seed2;

  /* generate padlen */
  tt_int_op(0, <=, random_bytes((uchar*)&plength2, 4));

  plength2 %= OBFUSCATE_MAX_PADDING;
  send_plength2 = htonl(plength2);

  uchar msgserver_1[OBFUSCATE_SEED_LENGTH + 8];
  uchar msgserver_2[OBFUSCATE_MAX_PADDING];

  seed2 = server_state->responder_seed;

  memcpy(msgserver_1, seed2, OBFUSCATE_SEED_LENGTH);
  memcpy(msgserver_1+OBFUSCATE_SEED_LENGTH, &magic, 4);
  memcpy(msgserver_1+OBFUSCATE_SEED_LENGTH+4, &send_plength2, 4);

  stream_crypt(server_state->send_padding_crypto,
               msgserver_1+OBFUSCATE_SEED_LENGTH, 8);

  /* Server sends handshake part 1 */
  evbuffer_add(conn_get_outbound(s->conn_server),
               msgserver_1, OBFUSCATE_SEED_LENGTH+8);

  /* Client receives handshake part 1 */
  conn_recv(s->conn_client);
  tt_int_op(ST_WAIT_FOR_PADDING, ==, client_state->state);

  /* Preparing client's handshake part 2 */
  tt_int_op(0, <=, random_bytes(msgserver_2, plength2));
  stream_crypt(server_state->send_padding_crypto, msgserver_2, plength2);

  /* Server sends handshake part 2 */
  evbuffer_add(conn_get_outbound(s->conn_server), msgserver_2, plength2);

  /* Client receives handshake part 2 */
  conn_recv(s->conn_client);
  tt_int_op(ST_OPEN, ==, client_state->state);

  /* The handshake is finally complete. We should have: */
  /*    client's send_crypto == server's recv_crypto */
  /*    server's send_crypto == client's recv_crypto . */
  tt_mem_op(client_state->send_crypto, ==, server_state->recv_crypto,
            sizeof(crypt_t));

  tt_mem_op(client_state->recv_crypto, ==, server_state->send_crypto,
            sizeof(crypt_t));

 end:;
}

/*
  Erroneous handshake test:
  Wrong magic value.
*/
static void
test_obfs2_wrong_handshake_magic(void *state)
{
  struct proto_test_state *s = state;
  obfs2_conn_t *client_state = downcast_conn(s->conn_client);
  obfs2_conn_t *server_state = downcast_conn(s->conn_server);

  uint32_t wrong_magic = 0xD15EA5E;

  uint32_t plength, send_plength;
  const uchar *seed;
  uchar msg[OBFUSCATE_MAX_PADDING + OBFUSCATE_SEED_LENGTH + 8];

  tt_int_op(0, >=, random_bytes((uchar*)&plength, 4));
  plength %= OBFUSCATE_MAX_PADDING;
  send_plength = htonl(plength);

  seed = client_state->initiator_seed;
  memcpy(msg, seed, OBFUSCATE_SEED_LENGTH);
  memcpy(msg+OBFUSCATE_SEED_LENGTH, &wrong_magic, 4);
  memcpy(msg+OBFUSCATE_SEED_LENGTH+4, &send_plength, 4);
  tt_int_op(0, >=, random_bytes(msg+OBFUSCATE_SEED_LENGTH+8, plength));

  stream_crypt(client_state->send_padding_crypto,
               msg+OBFUSCATE_SEED_LENGTH, 8+plength);

  evbuffer_add(conn_get_outbound(s->conn_client), msg,
               OBFUSCATE_SEED_LENGTH+8+plength);

  /* If we call conn_recv here, and everything's working correctly,
     it will blow away the connection before we can check for failure,
     so use the vtable method directly. */
  tt_int_op(RECV_BAD, ==,
            s->conn_server->cfg->vtable->conn_recv(s->conn_server));
  tt_int_op(ST_WAIT_FOR_KEY, ==, server_state->state);

 end:;
}

/* Erroneous handshake test:
   plength field larger than OBFUSCATE_MAX_PADDING
*/
static void
test_obfs2_wrong_handshake_plength(void *state)
{
  struct proto_test_state *s = state;
  obfs2_conn_t *client_state = downcast_conn(s->conn_client);
  obfs2_conn_t *server_state = downcast_conn(s->conn_server);

  uchar msg[OBFUSCATE_MAX_PADDING + OBFUSCATE_SEED_LENGTH + 8 + 1];
  uint32_t magic = htonl(OBFUSCATE_MAGIC_VALUE);
  uint32_t plength, send_plength;
  const uchar *seed;
  seed = client_state->initiator_seed;

  plength = OBFUSCATE_MAX_PADDING + 1U;
  send_plength = htonl(plength);

  memcpy(msg, seed, OBFUSCATE_SEED_LENGTH);
  memcpy(msg+OBFUSCATE_SEED_LENGTH, &magic, 4);
  memcpy(msg+OBFUSCATE_SEED_LENGTH+4, &send_plength, 4);
  tt_int_op(0, >=, random_bytes(msg+OBFUSCATE_SEED_LENGTH+8, plength));

  stream_crypt(client_state->send_padding_crypto,
               msg+OBFUSCATE_SEED_LENGTH, 8+plength);

  evbuffer_add(conn_get_outbound(s->conn_client), msg,
               OBFUSCATE_SEED_LENGTH+8+plength);

  /* If we call conn_recv here, and everything's working correctly,
     it will blow away the connection before we can check for failure,
     so use the vtable method directly. */
  tt_int_op(RECV_BAD, ==,
            s->conn_server->cfg->vtable->conn_recv(s->conn_server));
  tt_int_op(ST_WAIT_FOR_KEY, ==, server_state->state);

 end:;
}

static const char *const options_client[] =
  {"obfs2", "--shared-secret=hahaha", "socks", "127.0.0.1:1800"};

static const char *const options_server[] =
  {"obfs2", "--shared-secret=hahaha",
   "--dest=127.0.0.1:1500", "server", "127.0.0.1:1800"};

static const struct proto_test_args obfs2_args =
  { ALEN(options_client), ALEN(options_server),
    options_client, options_server };

#define T(name) \
  { #name, test_obfs2_##name, 0, &proto_test_fixture, (void *)&obfs2_args }

struct testcase_t obfs2_tests[] = {
  T(handshake),
  T(split_handshake),
  T(wrong_handshake_magic),
  T(wrong_handshake_plength),
  END_OF_TESTCASES
};
