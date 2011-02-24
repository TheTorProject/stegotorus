#if 0
/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tinytest.h"
#include "tinytest_macros.h"

#include <event2/buffer.h>
#include <openssl/aes.h>


#define CRYPT_PROTOCOL_PRIVATE
#define CRYPT_PRIVATE
#include "../crypt.h"
#include "../util.h"
#include "../crypt_protocol.h"

/* Make sure we can successfully set up a protocol state */
static void
test_proto_setup(void *data)
{
  protocol_state_t *proto1, *proto2;
  proto1 = protocol_state_new(1);
  proto2 = protocol_state_new(0);
  tt_assert(proto1);
  tt_assert(proto2);
 end:
  if (proto1)
    protocol_state_free(proto1);
  if (proto2)
    protocol_state_free(proto2);

}

static void
test_proto_handshake(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  protocol_state_t *client_state, *server_state;
  client_state = protocol_state_new(1);
  server_state = protocol_state_new(0);
  tt_assert(client_state);
  tt_assert(server_state);

  /* We create a client handshake message and pass it to output_buffer */
  tt_int_op(0, <=, proto_send_initial_message(client_state, output_buffer)<0);

  /* We simulate the server receiving and processing the client's handshake message,
     by using proto_recv() on the output_buffer */
  tt_int_op(0, <=, proto_recv(server_state, output_buffer, dummy_buffer) <0);

  /* Now, we create the server's handshake and pass it to output_buffer */
  tt_int_op(0, <=, proto_send_initial_message(server_state, output_buffer)<0);

  /* We simulate the client receiving and processing the server's handshake */
  tt_int_op(0, <=, proto_recv(client_state, output_buffer, dummy_buffer) <0);

  /* The handshake is now complete. We should have:
     client's send_crypto == server's recv_crypto
     server's send_crypto == client's recv_crypto . */
  tt_int_op(0, ==, memcmp(client_state->send_crypto,
                          server_state->recv_crypto,
                          sizeof(crypt_t)));

  tt_int_op(0, ==, memcmp(client_state->recv_crypto,
                          server_state->send_crypto,
                          sizeof(crypt_t)));

 end:
  if (client_state)
    protocol_state_free(client_state);
  if (server_state)
    protocol_state_free(server_state);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}

static void
test_proto_transfer(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  protocol_state_t *client_state, *server_state;
  client_state = protocol_state_new(1);
  server_state = protocol_state_new(0);
  tt_assert(client_state);
  tt_assert(server_state);

  int n;
  struct evbuffer_iovec v[2];

  /* Handshake */
  tt_int_op(0, <=, proto_send_initial_message(client_state, output_buffer)<0);
  tt_int_op(0, <=, proto_recv(server_state, output_buffer, dummy_buffer) <0);
  tt_int_op(0, <=, proto_send_initial_message(server_state, output_buffer)<0);
  tt_int_op(0, <=, proto_recv(client_state, output_buffer, dummy_buffer) <0);
  /* End of Handshake */

  /* Now let's pass some data around. */
  char *msg1 = "this is a 54-byte message passed from client to server";
  char *msg2 = "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(dummy_buffer, msg1, 54);
  proto_send(client_state, dummy_buffer, output_buffer);

  tt_int_op(0, <=, proto_recv(server_state, output_buffer, dummy_buffer));

  n = evbuffer_peek(dummy_buffer, -1, NULL, &v[0], 2);

  /* Let's check if it matches. */
  tt_int_op(0, ==, strncmp(msg1, v[0].iov_base, 54));

  /* emptying dummy_buffer before next test  */
  size_t buffer_len = evbuffer_get_length(dummy_buffer);
  tt_int_op(0, ==, evbuffer_drain(dummy_buffer, buffer_len));

  /* client <- server */
  evbuffer_add(dummy_buffer, msg2, 55);
  tt_int_op(0, <=, proto_send(server_state, dummy_buffer, output_buffer));

  tt_int_op(0, <=, proto_recv(client_state, output_buffer, dummy_buffer));

  n = evbuffer_peek(dummy_buffer, -1, NULL, &v[1], 2);
  tt_int_op(0, ==, strncmp(msg2, v[1].iov_base, 55));

 end:
  if (client_state)
    protocol_state_free(client_state);
  if (server_state)
    protocol_state_free(server_state);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
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
test_proto_splitted_handshake(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  protocol_state_t *client_state;
  protocol_state_t *server_state;
  client_state = protocol_state_new(1);
  server_state = protocol_state_new(0);
  tt_assert(client_state);
  tt_assert(server_state);

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
  tt_int_op(0, <=, random_bytes(msgclient_1+OBFUSCATE_SEED_LENGTH+8, plength1_msg1));

  stream_crypt(client_state->send_padding_crypto, msgclient_1+OBFUSCATE_SEED_LENGTH, 8+plength1_msg1);

  /* Client sends handshake part 1 */
  evbuffer_add(output_buffer, msgclient_1, OBFUSCATE_SEED_LENGTH+8+plength1_msg1);

  /* Server receives handshake part 1 */
  tt_int_op(0, <=, proto_recv(server_state, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_PADDING);

  /* Preparing client's handshake part 2 */
  tt_int_op(0, <=, random_bytes(msgclient_2, plength1_msg2));
  stream_crypt(client_state->send_padding_crypto, msgclient_2, plength1_msg2);

  /* Client sends handshake part 2 */
  evbuffer_add(output_buffer, msgclient_2, plength1_msg2);

  /* Server receives handshake part 2 */
  tt_int_op(0, <=, proto_recv(server_state, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_OPEN);

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

  stream_crypt(server_state->send_padding_crypto, msgserver_1+OBFUSCATE_SEED_LENGTH, 8);

  /* Server sends handshake part 1 */
  evbuffer_add(output_buffer, msgserver_1, OBFUSCATE_SEED_LENGTH+8);

  /* Client receives handshake part 1 */
  tt_int_op(0, <=, proto_recv(client_state, output_buffer, dummy_buffer));

  tt_assert(client_state->state == ST_WAIT_FOR_PADDING);

  /* Preparing client's handshake part 2 */
  tt_int_op(0, <=, random_bytes(msgserver_2, plength2));
  stream_crypt(server_state->send_padding_crypto, msgserver_2, plength2);

  /* Server sends handshake part 2 */
  evbuffer_add(output_buffer, msgserver_2, plength2);

  /* Client receives handshake part 2 */
  tt_int_op(0, <=, proto_recv(client_state, output_buffer, dummy_buffer));

  tt_assert(client_state->state == ST_OPEN);

  /* The handshake is finally complete. We should have: */
  /*    client's send_crypto == server's recv_crypto */
  /*    server's send_crypto == client's recv_crypto . */
  tt_int_op(0, ==, memcmp(client_state->send_crypto,
                          server_state->recv_crypto,
                          sizeof(crypt_t)));

  tt_int_op(0, ==, memcmp(client_state->recv_crypto,
                          server_state->send_crypto,
                          sizeof(crypt_t)));

 end:
  if (client_state)
    protocol_state_free(client_state);
  if (server_state)
    protocol_state_free(server_state);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}

/*
  Erroneous handshake test:
  Wrong magic value.
*/
static void
test_proto_wrong_handshake_magic(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  protocol_state_t *client_state;
  protocol_state_t *server_state;
  client_state = protocol_state_new(1);
  server_state = protocol_state_new(0);
  tt_assert(client_state);
  tt_assert(server_state);

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

  evbuffer_add(output_buffer, msg, OBFUSCATE_SEED_LENGTH+8+plength);

  tt_int_op(-1, ==, proto_recv(server_state, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_KEY);

 end:
  if (client_state)
    protocol_state_free(client_state);
  if (server_state)
    protocol_state_free(server_state);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}

#if 0
/*
  Erroneous handshake test:
  Normal plength field but actual padding larger than
  OBFUSCATE_MAX_PADDING.

  XXXX This won't actually fail.  If we send extra padding, it gets treated as
  part of the message.  Decrypting it will give odd results, but this protocol
  doesn't actually get you integrity.
*/
static void
test_proto_wrong_handshake_padding(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  protocol_state_t *client_state;
  protocol_state_t *server_state;
  client_state = protocol_state_new(1);
  server_state = protocol_state_new(0);
  tt_assert(client_state);
  tt_assert(server_state);

  uchar bigmsg[OBFUSCATE_MAX_PADDING + 1 + OBFUSCATE_SEED_LENGTH + 8];
  uint32_t actual_plength, fake_plength, send_plength;

  const uchar *seed;
  seed = client_state->initiator_seed;
  uint32_t magic = htonl(OBFUSCATE_MAGIC_VALUE);

  actual_plength = OBFUSCATE_MAX_PADDING + 1U;
  fake_plength = 666U;
  send_plength = htonl(fake_plength);

  memcpy(bigmsg, seed, OBFUSCATE_SEED_LENGTH);
  memcpy(bigmsg+OBFUSCATE_SEED_LENGTH, &magic, 4);
  memcpy(bigmsg+OBFUSCATE_SEED_LENGTH+4, &send_plength, 4);
  tt_int_op(0, >=, random_bytes(bigmsg+OBFUSCATE_SEED_LENGTH+8, actual_plength));

  stream_crypt(client_state->send_padding_crypto,
               bigmsg+OBFUSCATE_SEED_LENGTH, 8+actual_plength);

  evbuffer_add(output_buffer, bigmsg, OBFUSCATE_SEED_LENGTH+8+actual_plength);

  tt_int_op(-1, ==, proto_recv(server_state, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_KEY);

 end:
  if (client_state)
    protocol_state_free(client_state);
  if (server_state)
    protocol_state_free(server_state);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}
#endif

/* Erroneous handshake test:
   plength field larger than OBFUSCATE_MAX_PADDING
*/
static void
test_proto_wrong_handshake_plength(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  protocol_state_t *client_state;
  protocol_state_t *server_state;
  client_state = protocol_state_new(1);
  server_state = protocol_state_new(0);
  tt_assert(client_state);
  tt_assert(server_state);

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

  evbuffer_add(output_buffer, msg, OBFUSCATE_SEED_LENGTH+8+plength);

  tt_int_op(-1, ==, proto_recv(server_state, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_KEY);

 end:
  if (client_state)
    protocol_state_free(client_state);
  if (server_state)
    protocol_state_free(server_state);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}


#define T(name, flags) \
  { #name, test_proto_##name, (flags), NULL, NULL }

struct testcase_t protocol_tests[] = {
  T(setup, 0),
  T(handshake, 0),
  T(transfer, 0),
  T(splitted_handshake, 0),
  T(wrong_handshake_magic, 0),
#if 0
  T(wrong_handshake_padding, 0),
#endif
  T(wrong_handshake_plength, 0),
  END_OF_TESTCASES
};
#endif
