/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "tinytest.h"
#include "tinytest_macros.h"

#define PROTOCOL_OBFS2_PRIVATE
#define CRYPT_PRIVATE
#include "../protocols/obfs2.h"
#include "../crypt.h"
#include "../util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>

#define ALEN(x) (sizeof x/sizeof x[0])
#define OPTV(name) static const char *const name[]

static inline obfs2_protocol_t *
downcast(struct protocol_t *proto)
{
  return (obfs2_protocol_t *)
    ((char *)proto - offsetof(obfs2_protocol_t, super));
}

static void
test_obfs2_option_parsing(void *data)
{
  /* Suppress logs for the duration of this function. */
  log_set_method(LOG_METHOD_NULL, NULL);

  /** good option list */
  OPTV(options1) = {"obfs2", "--shared-secret=a", "socks", "127.0.0.1:0"};
  tt_assert(proto_params_init(ALEN(options1), options1) != NULL);

  /** two --dest. */
  OPTV(options2) = {"obfs2", "--dest=127.0.0.1:5555", "--dest=a",
                    "server", "127.0.0.1:5552"};
  tt_assert(proto_params_init(ALEN(options2), options2) == NULL);

  /** unknown arg */
  OPTV(options3) = {"obfs2", "--gabura=a", "server", "127.0.0.1:5552"};
  tt_assert(proto_params_init(ALEN(options3), options3) == NULL)

  /** too many args */
  OPTV(options4) = {"obfs2", "1", "2", "3", "4", "5" };
  tt_assert(proto_params_init(ALEN(options4), options4) == NULL)

  /** wrong mode  */
  OPTV(options5) = {"obfs2", "--dest=1:1", "gladiator", "127.0.0.1:5552"};
  tt_assert(proto_params_init(ALEN(options5), options5) == NULL)

  /** bad listen addr.  */
  OPTV(options6) = {"obfs2", "--dest=1:1", "server", "127.0.0.1:a"};
  tt_assert(proto_params_init(ALEN(options6), options6) == NULL)

  /** bad dest addr.  */
  OPTV(options7) = {"obfs2", "--dest=1:b", "server", "127.0.0.1:1"};
  tt_assert(proto_params_init(ALEN(options7), options7) == NULL)

  /** socks with dest.  */
  OPTV(options8) = {"obfs2", "--dest=1:2", "socks", "127.0.0.1:1"};
  tt_assert(proto_params_init(ALEN(options8), options8) == NULL)

  /** socks with dest.  */
  OPTV(options9) = {"obfs2", "--shared-secret=a", "server", "127.0.0.1:1"};
  tt_assert(proto_params_init(ALEN(options9), options9) == NULL)

 end:
  /* Unsuspend logging */
  log_set_method(LOG_METHOD_STDOUT, NULL);
}

/* Make sure we can successfully set up a protocol state */
static void
test_obfs2_setup(void *data)
{
  struct protocol_t *client_proto = NULL;
  struct protocol_t *server_proto = NULL;
  struct protocol_params_t *proto_params_client = NULL;
  struct protocol_params_t *proto_params_server = NULL;

  OPTV(options_client) = {"obfs2", "--shared-secret=hahaha",
                          "socks", "127.0.0.1:1800"};
  proto_params_client = proto_params_init(ALEN(options_client), options_client);
  tt_assert(proto_params_client);

  OPTV(options_server) = {"obfs2", "--shared-secret=hahaha",
                          "--dest=127.0.0.1:1500",
                          "server", "127.0.0.1:1800"};
  proto_params_server = proto_params_init(ALEN(options_server), options_server);
  tt_assert(proto_params_server);

  client_proto = proto_create(proto_params_client);
  tt_assert(client_proto);

  server_proto = proto_create(proto_params_server);
  tt_assert(server_proto);

 end:;
  if (client_proto)
      proto_destroy(client_proto);
  if (server_proto)
      proto_destroy(server_proto);

  if (proto_params_client)
    proto_params_free(proto_params_client);
  if (proto_params_server)
    proto_params_free(proto_params_server);
}

static void
test_obfs2_handshake(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  struct protocol_t *client_proto = NULL;
  struct protocol_t *server_proto = NULL;
  struct protocol_params_t *proto_params_client = NULL;
  struct protocol_params_t *proto_params_server = NULL;

  OPTV(options_client) = {"obfs2", "--shared-secret=hahaha",
                          "socks", "127.0.0.1:1800"};
  proto_params_client = proto_params_init(ALEN(options_client), options_client);
  tt_assert(proto_params_client);

  OPTV(options_server) = {"obfs2", "--shared-secret=hahaha",
                          "--dest=127.0.0.1:1500",
                          "server", "127.0.0.1:1800"};
  proto_params_server = proto_params_init(ALEN(options_server), options_server);
  tt_assert(proto_params_server);

  client_proto = proto_create(proto_params_client);
  tt_assert(client_proto);

  server_proto = proto_create(proto_params_server);
  tt_assert(server_proto);

  obfs2_protocol_t *client_state = downcast(client_proto);
  obfs2_protocol_t *server_state = downcast(server_proto);

  /* We create a client handshake message and pass it to output_buffer */
  tt_int_op(0, <=, proto_handshake(client_proto, output_buffer));

  /* We simulate the server receiving and processing the client's
     handshake message, by using proto_recv() on the output_buffer */
  tt_assert(RECV_GOOD == proto_recv(server_proto, output_buffer, dummy_buffer));

  /* Now, we create the server's handshake and pass it to output_buffer */
  tt_int_op(0, <=, proto_handshake(server_proto, output_buffer));

  /* We simulate the client receiving and processing the server's handshake */
  tt_assert(RECV_GOOD == proto_recv(client_proto, output_buffer, dummy_buffer));

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
  if (client_proto)
      proto_destroy(client_proto);
  if (server_proto)
      proto_destroy(server_proto);

  if (proto_params_client)
    proto_params_free(proto_params_client);
  if (proto_params_server)
    proto_params_free(proto_params_server);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}

static void
test_obfs2_transfer(void *data)
{
  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  struct protocol_t *client_proto = NULL;
  struct protocol_t *server_proto = NULL;
  struct protocol_params_t *proto_params_client = NULL;
  struct protocol_params_t *proto_params_server = NULL;

  OPTV(options_client) = {"obfs2", "--shared-secret=hahaha",
                          "socks", "127.0.0.1:1800"};
  proto_params_client = proto_params_init(ALEN(options_client), options_client);
  tt_assert(proto_params_client);

  OPTV(options_server) = {"obfs2", "--shared-secret=hahaha",
                          "--dest=127.0.0.1:1500",
                          "server", "127.0.0.1:1800"};
  proto_params_server = proto_params_init(ALEN(options_server), options_server);
  tt_assert(proto_params_server);

  client_proto = proto_create(proto_params_client);
  tt_assert(client_proto);

  server_proto = proto_create(proto_params_server);
  tt_assert(server_proto);

  int n;
  struct evbuffer_iovec v[2];

  /* Handshake */
  tt_int_op(0, <=, proto_handshake(client_proto, output_buffer));
  tt_assert(RECV_GOOD == proto_recv(server_proto, output_buffer, dummy_buffer));
  tt_int_op(0, <=, proto_handshake(server_proto, output_buffer));
  tt_assert(RECV_GOOD == proto_recv(client_proto, output_buffer, dummy_buffer));
  /* End of Handshake */

  /* Now let's pass some data around. */
  char *msg1 = "this is a 54-byte message passed from client to server";
  char *msg2 = "this is a 55-byte message passed from server to client!";

  /* client -> server */
  evbuffer_add(dummy_buffer, msg1, 54);
  proto_send(client_proto, dummy_buffer, output_buffer);

  tt_assert(RECV_GOOD == proto_recv(server_proto, output_buffer, dummy_buffer));

  n = evbuffer_peek(dummy_buffer, -1, NULL, &v[0], 2);
  tt_int_op(n, !=, -1);

  /* Let's check if it matches. */
  tt_int_op(0, ==, strncmp(msg1, v[0].iov_base, 54));

  /* emptying dummy_buffer before next test  */
  size_t buffer_len = evbuffer_get_length(dummy_buffer);
  tt_int_op(0, ==, evbuffer_drain(dummy_buffer, buffer_len));

  /* client <- server */
  evbuffer_add(dummy_buffer, msg2, 55);
  tt_int_op(0, <=, proto_send(server_proto, dummy_buffer, output_buffer));

  tt_assert(RECV_GOOD == proto_recv(client_proto, output_buffer, dummy_buffer));

  n = evbuffer_peek(dummy_buffer, -1, NULL, &v[1], 2);
  tt_int_op(0, ==, strncmp(msg2, v[1].iov_base, 55));

  (void) n; /* XXXX: use n for something, or remove it. */

 end:
  if (client_proto)
    proto_destroy(client_proto);
  if (server_proto)
    proto_destroy(server_proto);

  if (proto_params_client)
    proto_params_free(proto_params_client);
  if (proto_params_server)
    proto_params_free(proto_params_server);

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
test_obfs2_split_handshake(void *data)
{
  obfs2_protocol_t *client_state = NULL;
  obfs2_protocol_t *server_state = NULL;

  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  struct protocol_t *client_proto = NULL;
  struct protocol_t *server_proto = NULL;
  struct protocol_params_t *proto_params_client = NULL;
  struct protocol_params_t *proto_params_server = NULL;

  OPTV(options_client) = {"obfs2", "--shared-secret=hahaha",
                          "socks", "127.0.0.1:1800"};
  proto_params_client = proto_params_init(ALEN(options_client), options_client);
  tt_assert(proto_params_client);

  OPTV(options_server) = {"obfs2", "--shared-secret=hahaha",
                          "--dest=127.0.0.1:1500",
                          "server", "127.0.0.1:1800"};
  proto_params_server = proto_params_init(ALEN(options_server), options_server);
  tt_assert(proto_params_server);

  client_proto = proto_create(proto_params_client);
  tt_assert(client_proto);

  server_proto = proto_create(proto_params_server);
  tt_assert(server_proto);

  client_state = downcast(client_proto);
  server_state = downcast(server_proto);

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
  evbuffer_add(output_buffer, msgclient_1,
               OBFUSCATE_SEED_LENGTH+8+plength1_msg1);

  /* Server receives handshake part 1 */
  tt_assert(RECV_INCOMPLETE == proto_recv(server_proto,
                                          output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_PADDING);

  /* Preparing client's handshake part 2 */
  tt_int_op(0, <=, random_bytes(msgclient_2, plength1_msg2));
  stream_crypt(client_state->send_padding_crypto, msgclient_2, plength1_msg2);

  /* Client sends handshake part 2 */
  evbuffer_add(output_buffer, msgclient_2, plength1_msg2);

  /* Server receives handshake part 2 */
  tt_assert(RECV_GOOD == proto_recv(server_proto, output_buffer, dummy_buffer));

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

  stream_crypt(server_state->send_padding_crypto,
               msgserver_1+OBFUSCATE_SEED_LENGTH, 8);

  /* Server sends handshake part 1 */
  evbuffer_add(output_buffer, msgserver_1, OBFUSCATE_SEED_LENGTH+8);

  /* Client receives handshake part 1 */
  tt_assert(RECV_INCOMPLETE == proto_recv(client_proto,
                                          output_buffer, dummy_buffer));

  tt_assert(client_state->state == ST_WAIT_FOR_PADDING);

  /* Preparing client's handshake part 2 */
  tt_int_op(0, <=, random_bytes(msgserver_2, plength2));
  stream_crypt(server_state->send_padding_crypto, msgserver_2, plength2);

  /* Server sends handshake part 2 */
  evbuffer_add(output_buffer, msgserver_2, plength2);

  /* Client receives handshake part 2 */
  tt_assert(RECV_GOOD == proto_recv(client_proto, output_buffer, dummy_buffer));

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
    proto_destroy(client_proto);
  if (server_state)
    proto_destroy(server_proto);

  if (proto_params_client)
    proto_params_free(proto_params_client);
  if (proto_params_server)
    proto_params_free(proto_params_server);

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
test_obfs2_wrong_handshake_magic(void *data)
{
  obfs2_protocol_t *client_state = NULL;
  obfs2_protocol_t *server_state = NULL;

  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  struct protocol_t *client_proto = NULL;
  struct protocol_t *server_proto = NULL;
  struct protocol_params_t *proto_params_client = NULL;
  struct protocol_params_t *proto_params_server = NULL;

  OPTV(options_client) = {"obfs2", "--shared-secret=hahaha",
                          "socks", "127.0.0.1:1800"};
  proto_params_client = proto_params_init(ALEN(options_client), options_client);
  tt_assert(proto_params_client);

  OPTV(options_server) = {"obfs2", "--shared-secret=hahaha",
                          "--dest=127.0.0.1:1500",
                          "server", "127.0.0.1:1800"};
  proto_params_server = proto_params_init(ALEN(options_server), options_server);
  tt_assert(proto_params_server);

  client_proto = proto_create(proto_params_client);
  tt_assert(client_proto);

  server_proto = proto_create(proto_params_server);
  tt_assert(server_proto);

  client_state = downcast(client_proto);
  server_state = downcast(server_proto);

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

  tt_assert(RECV_BAD == proto_recv(server_proto, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_KEY);

 end:
  if (client_state)
    proto_destroy(client_proto);
  if (server_state)
    proto_destroy(server_proto);

  if (proto_params_client)
    proto_params_free(proto_params_client);
  if (proto_params_server)
    proto_params_free(proto_params_server);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}

/* Erroneous handshake test:
   plength field larger than OBFUSCATE_MAX_PADDING
*/
static void
test_obfs2_wrong_handshake_plength(void *data)
{
  obfs2_protocol_t *client_state = NULL;
  obfs2_protocol_t *server_state = NULL;

  struct evbuffer *output_buffer = NULL;
  struct evbuffer *dummy_buffer = NULL;
  output_buffer = evbuffer_new();
  dummy_buffer = evbuffer_new();

  struct protocol_t *client_proto = NULL;
  struct protocol_t *server_proto = NULL;
  struct protocol_params_t *proto_params_client = NULL;
  struct protocol_params_t *proto_params_server = NULL;

  OPTV(options_client) = {"obfs2", "--shared-secret=hahaha",
                          "socks", "127.0.0.1:1800"};
  proto_params_client = proto_params_init(ALEN(options_client), options_client);
  tt_assert(proto_params_client);

  OPTV(options_server) = {"obfs2", "--shared-secret=hahaha",
                          "--dest=127.0.0.1:1500",
                          "server", "127.0.0.1:1800"};
  proto_params_server = proto_params_init(ALEN(options_server), options_server);
  tt_assert(proto_params_server);

  client_proto = proto_create(proto_params_client);
  tt_assert(client_proto);

  server_proto = proto_create(proto_params_server);
  tt_assert(server_proto);

  client_state = downcast(client_proto);
  server_state = downcast(server_proto);

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


  tt_assert(RECV_BAD == proto_recv(server_proto, output_buffer, dummy_buffer));

  tt_assert(server_state->state == ST_WAIT_FOR_KEY);

 end:
  if (client_proto)
    proto_destroy(client_proto);
  if (server_proto)
    proto_destroy(server_proto);

  if (proto_params_client)
    proto_params_free(proto_params_client);
  if (proto_params_server)
    proto_params_free(proto_params_server);

  if (output_buffer)
    evbuffer_free(output_buffer);
  if (dummy_buffer)
    evbuffer_free(dummy_buffer);
}

#define T(name) \
  { #name, test_obfs2_##name, 0, NULL, NULL }

struct testcase_t obfs2_tests[] = {
  T(option_parsing),
  T(setup),
  T(handshake),
  T(transfer),
  T(split_handshake),
  T(wrong_handshake_magic),
  T(wrong_handshake_plength),
  END_OF_TESTCASES
};
