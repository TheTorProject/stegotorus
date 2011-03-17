/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <event2/buffer.h>

#define CRYPT_PROTOCOL_PRIVATE

#include "obfs2_crypt.h"
#include "obfs2.h"
#include "../util.h"
#include "../protocol.h"

/* Sets the function table for the obfs2 protocol and
   calls initialize_crypto(). 
   Returns 0 on success, -1 on fail.
*/
int
obfs2_new(struct protocol_t *proto_struct) {
  proto_struct->destroy = (void *)obfs2_state_free;
  proto_struct->init = (void *)obfs2_state_new;
  proto_struct->handshake = (void *)obfs2_send_initial_message;
  proto_struct->send = (void *)obfs2_send;
  proto_struct->recv = (void *)obfs2_recv;

  if (initialize_crypto() < 0) {
    fprintf(stderr, "Can't initialize crypto; failing\n");
    return -1;
  }

  return 0;
}

/** Return true iff the OBFUSCATE_SEED_LENGTH-byte seed in 'seed' is nonzero */
static int
seed_nonzero(const uchar *seed)
{
  return memcmp(seed, OBFUSCATE_ZERO_SEED, OBFUSCATE_SEED_LENGTH) != 0;
}

/**
   Derive and return key of type 'keytype' from the seeds currently set in
   'state'.  Returns NULL on failure.
 */
static crypt_t *
derive_key(obfs2_state_t *state, const char *keytype)
{
  crypt_t *cryptstate;
  uchar buf[32];
  digest_t *c = digest_new();
  digest_update(c, (uchar*)keytype, strlen(keytype));
  if (seed_nonzero(state->initiator_seed))
    digest_update(c, state->initiator_seed, OBFUSCATE_SEED_LENGTH);
  if (seed_nonzero(state->responder_seed))
    digest_update(c, state->responder_seed, OBFUSCATE_SEED_LENGTH);
  if (seed_nonzero(state->secret_seed))
    digest_update(c, state->secret_seed, SHARED_SECRET_LENGTH);
  digest_update(c, (uchar*)keytype, strlen(keytype));
  digest_getdigest(c, buf, sizeof(buf));
  cryptstate = crypt_new(buf, 16);
  crypt_set_iv(cryptstate, buf+16, 16);
  memset(buf, 0, sizeof(buf));
  digest_free(c);
  return cryptstate;
}

static crypt_t *
derive_padding_key(obfs2_state_t *state, const uchar *seed,
                   const char *keytype)
{
  crypt_t *cryptstate;
  uchar buf[32];
  digest_t *c = digest_new();
  digest_update(c, (uchar*)keytype, strlen(keytype));
  if (seed_nonzero(seed))
    digest_update(c, seed, OBFUSCATE_SEED_LENGTH);
  if (seed_nonzero(state->secret_seed))
    digest_update(c, state->secret_seed, OBFUSCATE_SEED_LENGTH);
  digest_update(c, (uchar*)keytype, strlen(keytype));
  digest_getdigest(c, buf, sizeof(buf));
  cryptstate = crypt_new(buf, 16);
  crypt_set_iv(cryptstate, buf+16, 16);
  memset(buf, 0, 16);
  digest_free(c);
  return cryptstate;
}

/**
   Return a new object to handle protocol state.  If 'initiator' is true,
   we're the handshake initiator.  Otherwise, we're the responder.  Return
   NULL on failure.
 */
obfs2_state_t *
obfs2_state_new(int *initiator)
{
  obfs2_state_t *state = calloc(1, sizeof(obfs2_state_t));
  uchar *seed;
  const char *send_pad_type;

  if (!state)
    return NULL;
  state->state = ST_WAIT_FOR_KEY;
  state->we_are_initiator = *initiator;
  if (*initiator) {
    send_pad_type = INITIATOR_PAD_TYPE;
    seed = state->initiator_seed;
  } else {
    send_pad_type = RESPONDER_PAD_TYPE;
    seed = state->responder_seed;
  }

  /* Generate our seed */
  if (random_bytes(seed, OBFUSCATE_SEED_LENGTH) < 0) {
    free(state);
    return NULL;
  }

  /* Derive the key for what we're sending */
  state->send_padding_crypto = derive_padding_key(state, seed, send_pad_type);
  if (state->send_padding_crypto == NULL) {
    free(state);
    return NULL;
  }

  return state;
}

/** Set the shared secret to be used with this protocol state. */
void
obfs2_state_set_shared_secret(obfs2_state_t *state,
                                 const char *secret, size_t secretlen)
{
  if (secretlen > SHARED_SECRET_LENGTH)
    secretlen = SHARED_SECRET_LENGTH;
  memcpy(state->secret_seed, secret, secretlen);
}

/**
   Write the initial protocol setup and padding message for 'state' to
   the evbuffer 'buf'.  Return 0 on success, -1 on failure.
 */
int
obfs2_send_initial_message(obfs2_state_t *state, struct evbuffer *buf)
{
  uint32_t magic = htonl(OBFUSCATE_MAGIC_VALUE), plength, send_plength;
  uchar msg[OBFUSCATE_MAX_PADDING + OBFUSCATE_SEED_LENGTH + 8];
  const uchar *seed;

  /* We're going to send:
      SEED | E_PAD_KEY( UINT32(MAGIC_VALUE) | UINT32(PADLEN) | WR(PADLEN) )
  */

  assert(sizeof(magic) == 4);

  /* generate padlen */
  if (random_bytes((uchar*)&plength, 4) < 0)
    return -1;
  plength %= OBFUSCATE_MAX_PADDING;
  send_plength = htonl(plength);

  printf("death and dest\n");

  if (state->we_are_initiator)
    seed = state->initiator_seed;
  else
    seed = state->responder_seed;

  /* Marshal the message, but with no parts encrypted */
  memcpy(msg, seed, OBFUSCATE_SEED_LENGTH);
  memcpy(msg+OBFUSCATE_SEED_LENGTH, &magic, 4);
  memcpy(msg+OBFUSCATE_SEED_LENGTH+4, &send_plength, 4);
  if (random_bytes(msg+OBFUSCATE_SEED_LENGTH+8, plength) < 0)
    return -1;

  /* Encrypt it */
  stream_crypt(state->send_padding_crypto,
               msg+OBFUSCATE_SEED_LENGTH, 8+plength);

  /* Put it on the buffer */
  evbuffer_add(buf, msg, OBFUSCATE_SEED_LENGTH+8+plength);
  return 0;
}

/**
   Helper: encrypt every byte from 'source' using the key in 'crypto',
   and write those bytes onto 'dest'.  Return 0 on success, -1 on failure.
 */
static int
crypt_and_transmit(crypt_t *crypto,
                   struct evbuffer *source, struct evbuffer *dest)
{
  uchar data[1024];
  while (1) {
    int n = evbuffer_remove(source, data, 1024);
    if (n <= 0)
      return 0;
    stream_crypt(crypto, data, n);
    // printf("Message is: %s", data);
    evbuffer_add(dest, data, n);
    dbg(("Processed %d bytes.", n));
  }
}

/**
   Called when data arrives from the user side and we want to send the
   obfuscated version.  Copies and obfuscates data from 'source' into 'dest'
   using the state in 'state'.  Returns 0 on success, -1 on failure.
 */
int
obfs2_send(obfs2_state_t *state,
          struct evbuffer *source, struct evbuffer *dest)
{
  if (state->send_crypto) {
    /* Our crypto is set up; just relay the bytes */
    return crypt_and_transmit(state->send_crypto, source, dest);
  } else {
    /* Our crypto isn't set up yet, we'll have to queue the data */
    if (evbuffer_get_length(source)) {
      if (! state->pending_data_to_send) {
        state->pending_data_to_send = evbuffer_new();
      }
      evbuffer_add_buffer(state->pending_data_to_send, source);
    }
    return 0;
  }
}

/**
   Helper: called after reciving our partner's setup message.  Initializes all
   keys.  Returns 0 on success, -1 on failure.
 */
static int
init_crypto(obfs2_state_t *state)
{
  const char *send_keytype;
  const char *recv_keytype;
  const char *recv_pad_keytype;
  const uchar *recv_seed;

  if (state->we_are_initiator) {
    send_keytype = INITIATOR_SEND_TYPE;
    recv_keytype = RESPONDER_SEND_TYPE;
    recv_pad_keytype = RESPONDER_PAD_TYPE;
    recv_seed = state->responder_seed;
  } else {
    send_keytype = RESPONDER_SEND_TYPE;
    recv_keytype = INITIATOR_SEND_TYPE;
    recv_pad_keytype = INITIATOR_PAD_TYPE;
    recv_seed = state->initiator_seed;
  }

  /* Derive all of the keys that depend on our partner's seed */
  state->send_crypto = derive_key(state, send_keytype);
  state->recv_crypto = derive_key(state, recv_keytype);
  state->recv_padding_crypto =
    derive_padding_key(state, recv_seed, recv_pad_keytype);

  if (state->send_crypto && state->recv_crypto && state->recv_padding_crypto)
    return 0;
  else
    return -1;
}

/* Called when we receive data in an evbuffer 'source': deobfuscates that data
 * and writes it to 'dest'.
 *
 * Returns x for "don't call again till you have x bytes".  0 for "all ok". -1
 * for "fail, close" */
int
obfs2_recv(obfs2_state_t *state, struct evbuffer *source,
           struct evbuffer *dest)
{
  if (state->state == ST_WAIT_FOR_KEY) {
    /* We're waiting for the first OBFUSCATE_SEED_LENGTH+8 bytes to show up
     * so we can learn the partner's seed and padding length */
    uchar buf[OBFUSCATE_SEED_LENGTH+8], *other_seed;
    uint32_t magic, plength;
    if (evbuffer_get_length(source) < OBFUSCATE_SEED_LENGTH+8) {
      /* data not here yet */
      return OBFUSCATE_SEED_LENGTH+8;
    }
    evbuffer_remove(source, buf, OBFUSCATE_SEED_LENGTH+8);

    if (state->we_are_initiator)
      other_seed = state->responder_seed;
    else
      other_seed = state->initiator_seed;

    memcpy(other_seed, buf, OBFUSCATE_SEED_LENGTH);

    /* Now we can set up all the keys from the seed */
    if (init_crypto(state) < 0)
      return -1;

    /* Decrypt the next 8 bytes */
    stream_crypt(state->recv_padding_crypto, buf+OBFUSCATE_SEED_LENGTH, 8);
    /* Check the magic number and extract the padding length */
    memcpy(&magic, buf+OBFUSCATE_SEED_LENGTH, 4);
    memcpy(&plength, buf+OBFUSCATE_SEED_LENGTH+4, 4);
    magic = ntohl(magic);
    plength = ntohl(plength);
    if (magic != OBFUSCATE_MAGIC_VALUE)
      return -1;
    if (plength > OBFUSCATE_MAX_PADDING)
      return -1;

    /* Send any data that we've been waiting to send */
    if (state->pending_data_to_send) {
      crypt_and_transmit(state->send_crypto, state->pending_data_to_send, dest);
      evbuffer_free(state->pending_data_to_send);
      state->pending_data_to_send = NULL;
    }

    /* Now we're waiting for plength bytes of padding */
    state->padding_left_to_read = plength;
    state->state = ST_WAIT_FOR_PADDING;

    /* Fall through here: if there is padding data waiting on the buffer, pull
       it off immediately. */
    dbg(("Received key, expecting %d bytes of padding\n", plength));
  }

  /* If we're still looking for padding, start pulling off bytes and
     discarding them. */
  while (state->padding_left_to_read) {
    int n = state->padding_left_to_read;
    size_t sourcelen = evbuffer_get_length(source);
    if (!sourcelen)
      return n;
    if ((size_t) n > evbuffer_get_length(source))
      n = evbuffer_get_length(source);
    evbuffer_drain(source, n);
    state->padding_left_to_read -= n;
    dbg(("Received %d bytes of padding; %d left to read\n", n,
         state->padding_left_to_read));
  }

  /* Okay; now we're definitely open.  Process whatever data we have. */
  state->state = ST_OPEN;

  dbg(("Processing %d bytes data onto destination buffer\n",
       (int) evbuffer_get_length(source)));
  return crypt_and_transmit(state->recv_crypto, source, dest);
}

void
obfs2_state_free(obfs2_state_t *s)
{
  if (s->send_crypto)
    crypt_free(s->send_crypto);
  if (s->send_padding_crypto)
    crypt_free(s->send_padding_crypto);
  if (s->recv_crypto)
    crypt_free(s->recv_crypto);
  if (s->recv_padding_crypto)
    crypt_free(s->recv_padding_crypto);
  if (s->pending_data_to_send)
    evbuffer_free(s->pending_data_to_send);
  memset(s, 0x0a, sizeof(obfs2_state_t));
  free(s);
}
