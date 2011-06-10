/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
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
#include "../network.h"
#include "../util.h"
#include "../protocol.h"
#include "../network.h"

static void obfs2_state_free(void *state);
static int obfs2_send_initial_message(void *state, struct evbuffer *buf);
static int obfs2_send(void *state,
                      struct evbuffer *source, struct evbuffer *dest);
static enum recv_ret obfs2_recv(void *state, struct evbuffer *source,
                                struct evbuffer *dest);
static void *obfs2_state_new(protocol_params_t *params); 
static int obfs2_state_set_shared_secret(void *s,
                                         const char *secret,
                                         size_t secretlen);
static int set_up_vtable(void);
static void usage(void);

static protocol_vtable *vtable=NULL;

/* 
   This function parses 'options' and fills the protocol parameters
   structure 'params'.
   It then fills the obfs2 vtable and initializes the crypto subsystem.

   Returns 0 on success, -1 on fail.
*/
int
obfs2_init(int n_options, char **options, 
           struct protocol_params_t *params)
{
  if (parse_and_set_options(n_options,options,params) < 0) {
    usage();
    return -1;
  }

  if (set_up_vtable() < 0)
    return -1;

  if (initialize_crypto() < 0) {
    fprintf(stderr, "Can't initialize crypto; failing\n");
    return -1;
  }

  return 1;
}

/**
   Helper: Parses 'options' and fills 'params'.
*/
int
parse_and_set_options(int n_options, char **options, 
                      struct protocol_params_t *params)
{
  struct sockaddr_storage ss_listen;
  int sl_listen;
  int got_dest=0;
  int got_ss=0;
  const char* defport;

  if ((n_options < 3) || (n_options > 5)) {
    log_warn("%s(): wrong options number: %d", __func__, n_options);
    return -1;
  }

  assert(!strcmp(*options,"obfs2"));
  params->proto = OBFS2_PROTOCOL;
  options++;

  /* Now parse the optional arguments */
  while (!strncmp(*options,"--",2)) {
      if (!strncmp(*options,"--dest=",7)) {
        if (got_dest)
          return -1;
        struct sockaddr_storage ss_target;
        struct sockaddr *sa_target=NULL;
        int sl_target=0;
        if (resolve_address_port(*options+7, 1, 0,
                                 &ss_target, &sl_target, NULL) < 0)
          return -1;
        assert(sl_target <= sizeof(struct sockaddr_storage));
        sa_target = (struct sockaddr *)&ss_target;
        memcpy(&params->target_address, sa_target, sl_target);
        params->target_address_len = sl_target;
        got_dest=1;
      } else if (!strncmp(*options,"--shared-secret=",16)) {
        if (got_ss)
          return -1;
        /* this is freed in protocol_params_free() */
        params->shared_secret = strdup(*options+16);
        params->shared_secret_len = strlen(*options+16);
        got_ss=1;
      } else {
        log_warn("%s(): Unknown argument.", __func__);
        return -1;
      }
      options++;
    }

    if (!strcmp(*options, "client")) {
      defport = "48988"; /* bf5c */
      params->mode = LSN_SIMPLE_CLIENT;
    } else if (!strcmp(*options, "socks")) {
      defport = "23548"; /* 5bf5 */
      params->mode = LSN_SOCKS_CLIENT;
    } else if (!strcmp(*options, "server")) {
      defport = "11253"; /* 2bf5 */
      params->mode = LSN_SIMPLE_SERVER;
    } else {
      log_warn("%s(): only client/socks/server modes supported.", __func__);
      return -1;
    }
    options++;

    params->is_initiator = (params->mode != LSN_SIMPLE_SERVER);

    if (resolve_address_port(*options, 1, 1, 
                             &ss_listen, &sl_listen, defport) < 0)
      return -1;
    assert(sl_listen <= sizeof(struct sockaddr_storage));
    struct sockaddr *sa_listen=NULL;
    sa_listen = (struct sockaddr *)&ss_listen;
    memcpy(&params->on_address, sa_listen, sl_listen);
    params->on_address_len = sl_listen;

    /* Validate option selection. */
    if (got_dest && (params->mode == LSN_SOCKS_CLIENT)) {
      log_warn("%s(): You can't be on socks mode and have --dest.", __func__);
      return -1;
    }

    if (!got_dest && (params->mode != LSN_SOCKS_CLIENT)) {
      log_warn("%s(): client/server mode needs --dest.", __func__);
      return -1;
    }

    log_debug("%s(): Parsed obfs2 options nicely!", __func__);
    return 1;
}

/**
   Prints usage instructions for the obfs2 protocol.
*/
static void
usage(void)
{
  log_warn("You failed at creating a correct obfs2 line.\n"
         "obfs2 syntax:\n"
         "\tobfs2 [obfs2_args] obfs2_opts\n"
         "\t'obfs2_opts':\n"
         "\t\tmode ~ server|client|socks\n"
         "\t\tlisten address ~ host:port\n"
         "\t'obfs2_args':\n"
         "\t\tDestination Address ~ --dest=host:port\n"
         "\t\tShared Secret ~ --shared-secret=<secret>\n"
         "\tExample:\n"
         "\tobfsproxy --dest=127.0.0.1:666 --shared-secret=himitsu "
         "\tobfs2 server 127.0.0.1:1026");
}

/**
   Helper: Allocates space for the protocol vtable and populates it's
   function pointers.
   Returns 1 on success, -1 on fail.
*/
static int
set_up_vtable(void)
{
  /* XXX memleak. */
  vtable = calloc(1, sizeof(protocol_vtable));
  if (!vtable)
    return -1;
  
  vtable->destroy = obfs2_state_free;
  vtable->create = obfs2_new;
  vtable->handshake = obfs2_send_initial_message;
  vtable->send = obfs2_send;
  vtable->recv = obfs2_recv;
  
  return 1;
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
derive_key(void *s, const char *keytype)
{
  obfs2_state_t *state = s;
  crypt_t *cryptstate;
  uchar buf[SHA256_LENGTH];
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

  if (seed_nonzero(state->secret_seed)) {
    digest_t *d;
    int i;
    for (i=0; i < OBFUSCATE_HASH_ITERATIONS; i++) {
      d = digest_new();
      digest_update(d, buf, sizeof(buf));
      digest_getdigest(d, buf, sizeof(buf));
    }
  }

  cryptstate = crypt_new(buf, 16);
  crypt_set_iv(cryptstate, buf+16, 16);
  memset(buf, 0, sizeof(buf));
  digest_free(c);
  return cryptstate;
}

/**
   Derive and return padding key of type 'keytype' from the seeds
   currently set in state 's'.  Returns NULL on failure.
*/   
static crypt_t *
derive_padding_key(void *s, const uchar *seed,
                   const char *keytype)
{
  obfs2_state_t *state = s;

  crypt_t *cryptstate;
  uchar buf[SHA256_LENGTH];
  digest_t *c = digest_new();

  digest_update(c, (uchar*)keytype, strlen(keytype));
  if (seed_nonzero(seed))
    digest_update(c, seed, OBFUSCATE_SEED_LENGTH);
  if (seed_nonzero(state->secret_seed))
    digest_update(c, state->secret_seed, OBFUSCATE_SEED_LENGTH);
  digest_update(c, (uchar*)keytype, strlen(keytype));
  digest_getdigest(c, buf, sizeof(buf));

  if (seed_nonzero(state->secret_seed)) {
    digest_t *d;
    int i;
    for (i=0; i < OBFUSCATE_HASH_ITERATIONS; i++) {
      d = digest_new();
      digest_update(d, buf, sizeof(buf));
      digest_getdigest(d, buf, sizeof(buf));
    }
  }

  cryptstate = crypt_new(buf, 16);
  crypt_set_iv(cryptstate, buf+16, 16);
  memset(buf, 0, 16);
  digest_free(c);
  return cryptstate;
}

/**
   This is called everytime we get a connection for the obfs2
   protocol.
   
   It sets up the protocol vtable in 'proto_struct' and then attempts
   to create and return a protocol state according to the protocol
   parameters 'params'.
*/
void *
obfs2_new(struct protocol_t *proto_struct,
          protocol_params_t *params)
{
  assert(vtable);
  proto_struct->vtable = vtable;
  
  return obfs2_state_new(params);
}
  
/**
   Returns an obfs2 state according to the protocol parameters
   'params'. If something goes wrong it returns NULL.
 */
static void *
obfs2_state_new(protocol_params_t *params)
{
  obfs2_state_t *state = calloc(1, sizeof(obfs2_state_t));
  uchar *seed;
  const char *send_pad_type;

  if (!state)
    return NULL;
  state->state = ST_WAIT_FOR_KEY;
  state->we_are_initiator = params->is_initiator;
  if (state->we_are_initiator) {
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

  if (params->shared_secret)
    if (obfs2_state_set_shared_secret(state, 
                                      params->shared_secret, 
                                      params->shared_secret_len)<0)
      return NULL;

  /* Derive the key for what we're sending */
  state->send_padding_crypto = derive_padding_key(state, seed, send_pad_type);
  if (state->send_padding_crypto == NULL) {
    free(state);
    return NULL;
  }

  return state;
}

/** 
    Sets the shared 'secret' to be used, on the protocol state 's'.
*/
static int
obfs2_state_set_shared_secret(void *s, const char *secret, 
                              size_t secretlen)
{
  assert(secret);
  assert(secretlen);

  uchar buf[SHARED_SECRET_LENGTH];
  obfs2_state_t *state = s;

  /* ASN we must say in spec that we hash command line shared secret. */
  digest_t *c = digest_new();
  digest_update(c, (uchar*)secret, secretlen);
  digest_getdigest(c, buf, sizeof(buf));

  memcpy(state->secret_seed, buf, SHARED_SECRET_LENGTH);

  memset(buf,0,SHARED_SECRET_LENGTH);
  digest_free(c);

  return 0;
}

/**
   Write the initial protocol setup and padding message for state 's' to
   the evbuffer 'buf'.  Return 0 on success, -1 on failure.
 */
static int
obfs2_send_initial_message(void *s, struct evbuffer *buf)
{
  obfs2_state_t *state = s;

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
    evbuffer_add(dest, data, n);
    log_debug("%s(): Processed %d bytes.", __func__, n);
  }
}

/**
   Called when data arrives from the user side and we want to send the
   obfuscated version.  Copies and obfuscates data from 'source' into 'dest'
   using the state in 'state'.  Returns 0 on success, -1 on failure.
 */
static int
obfs2_send(void *s,
          struct evbuffer *source, struct evbuffer *dest)
{
  obfs2_state_t *state = s;

  if (state->send_crypto) {
    /* First of all, send any data that we've been waiting to send. */
    if (state->pending_data_to_send) {
      crypt_and_transmit(state->send_crypto, state->pending_data_to_send, dest);
      evbuffer_free(state->pending_data_to_send);
      state->pending_data_to_send = NULL;
    }
    /* Our crypto is set up; just relay the bytes */
    return crypt_and_transmit(state->send_crypto, source, dest);
  } else {
    /* Our crypto isn't set up yet, we'll have to queue the data */
    if (evbuffer_get_length(source)) {
      if (! state->pending_data_to_send) {
        if ((state->pending_data_to_send = evbuffer_new()) == NULL)
          return -1;
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
init_crypto(void *s)
{
  obfs2_state_t *state = s;

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
 * and writes it to 'dest', by using protocol state 's' to get crypto keys.
 *
 * It returns: 
 * RECV_GOOD to say that everything went fine.
 * RECV_BAD to say that something went bad.
 * RECV_INCOMPLETE to say that we need more data to form an opinion.
 * RECV_SEND_PENDING to say that everything went fine and on top of
 *  that we also have pending data that we have to send. This notifies
 *  our callers that they must call obfs2_send() immediately.
 */
static enum recv_ret
obfs2_recv(void *s, struct evbuffer *source,
           struct evbuffer *dest)
{
  obfs2_state_t *state = s;
  enum recv_ret r=0;

  if (state->state == ST_WAIT_FOR_KEY) {
    /* We're waiting for the first OBFUSCATE_SEED_LENGTH+8 bytes to show up
     * so we can learn the partner's seed and padding length */
    uchar buf[OBFUSCATE_SEED_LENGTH+8], *other_seed;
    uint32_t magic, plength;
    if (evbuffer_get_length(source) < OBFUSCATE_SEED_LENGTH+8) {
      /* data not here yet */
      return RECV_INCOMPLETE;
    }
    evbuffer_remove(source, buf, OBFUSCATE_SEED_LENGTH+8);

    if (state->we_are_initiator)
      other_seed = state->responder_seed;
    else
      other_seed = state->initiator_seed;

    memcpy(other_seed, buf, OBFUSCATE_SEED_LENGTH);

    /* Now we can set up all the keys from the seed */
    if (init_crypto(state) < 0)
      return RECV_BAD;

    /* Decrypt the next 8 bytes */
    stream_crypt(state->recv_padding_crypto, buf+OBFUSCATE_SEED_LENGTH, 8);
    /* Check the magic number and extract the padding length */
    memcpy(&magic, buf+OBFUSCATE_SEED_LENGTH, 4);
    memcpy(&plength, buf+OBFUSCATE_SEED_LENGTH+4, 4);
    magic = ntohl(magic);
    plength = ntohl(plength);
    if (magic != OBFUSCATE_MAGIC_VALUE)
      return RECV_BAD;
    if (plength > OBFUSCATE_MAX_PADDING)
      return RECV_BAD;

    /* Now we're waiting for plength bytes of padding */
    state->padding_left_to_read = plength;
    state->state = ST_WAIT_FOR_PADDING;

    /* Fall through here: if there is padding data waiting on the buffer, pull
       it off immediately. */
    log_debug("%s(): Received key, expecting %d bytes of padding", __func__, plength);
  }

  /* If we have pending data to send, we set the return code
  appropriately so that we call proto_send() right after we get out of
  here! */  
  if (state->pending_data_to_send)
    r = RECV_SEND_PENDING;

  /* If we're still looking for padding, start pulling off bytes and
     discarding them. */
  while (state->padding_left_to_read) {
    int n = state->padding_left_to_read;
    size_t sourcelen = evbuffer_get_length(source);
    if (!sourcelen)
      return RECV_INCOMPLETE;
    if ((size_t) n > evbuffer_get_length(source))
      n = evbuffer_get_length(source);
    evbuffer_drain(source, n);
    state->padding_left_to_read -= n;
    log_debug("%s(): Received %d bytes of padding; %d left to read", 
              __func__, n, state->padding_left_to_read);
  }

  /* Okay; now we're definitely open.  Process whatever data we have. */
  state->state = ST_OPEN;

  log_debug("%s(): Processing %d bytes data onto destination buffer",
            __func__, (int) evbuffer_get_length(source));
  crypt_and_transmit(state->recv_crypto, source, dest);

  if (r != RECV_SEND_PENDING)
    r = RECV_GOOD;

  return r;
}

/** 
    Frees obfs2 state 's' 
*/
static void
obfs2_state_free(void *s)
{
  obfs2_state_t *state = s;
  if (state->send_crypto)
    crypt_free(state->send_crypto);
  if (state->send_padding_crypto)
    crypt_free(state->send_padding_crypto);
  if (state->recv_crypto)
    crypt_free(state->recv_crypto);
  if (state->recv_padding_crypto)
    crypt_free(state->recv_padding_crypto);
  if (state->pending_data_to_send)
    evbuffer_free(state->pending_data_to_send);
  memset(state, 0x0a, sizeof(obfs2_state_t));
  free(state);
}
