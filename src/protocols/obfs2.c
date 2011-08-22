/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#define PROTOCOL_OBFS2_PRIVATE
#include "obfs2.h"

#include <event2/buffer.h>

PROTO_DEFINE_MODULE(obfs2, NOSTEG);

/**
   Helper: Parses 'options' and fills 'params'.
*/
static int
parse_and_set_options(int n_options, const char *const *options, config_t *c)
{
  int got_dest=0;
  int got_ss=0;
  const char* defport;
  obfs2_config_t *cfg = downcast_config(c);

  if ((n_options < 2) || (n_options > 4)) {
    log_warn("obfs2: wrong number of options: %d", n_options);
    return -1;
  }

  /* Now parse the optional arguments */
  while (!strncmp(*options,"--",2)) {
      if (!strncmp(*options,"--dest=",7)) {
        if (got_dest)
          return -1;
        cfg->target_addr = resolve_address_port(*options+7, 1, 0, NULL);
        if (!cfg->target_addr)
          return -1;
        got_dest=1;
      } else if (!strncmp(*options,"--shared-secret=",16)) {
        digest_t *digest;
        if (got_ss)
          return -1;

        /* ASN we must say in spec that we hash command line shared
           secret. */
        digest = digest_new();
        digest_update(digest, (uchar*)*options+16, strlen(*options+16));
        digest_getdigest(digest, cfg->shared_secret, SHARED_SECRET_LENGTH);
        digest_free(digest);

        got_ss=1;
      } else {
        log_warn("obfs2: Unknown argument.");
        return -1;
      }
      options++;
    }

    if (!strcmp(*options, "client")) {
      defport = "48988"; /* bf5c */
      c->mode = LSN_SIMPLE_CLIENT;
    } else if (!strcmp(*options, "socks")) {
      defport = "23548"; /* 5bf5 */
      c->mode = LSN_SOCKS_CLIENT;
    } else if (!strcmp(*options, "server")) {
      defport = "11253"; /* 2bf5 */
      c->mode = LSN_SIMPLE_SERVER;
    } else {
      log_warn("obfs2: only client/socks/server modes supported.");
      return -1;
    }
    options++;

    cfg->listen_addr = resolve_address_port(*options, 1, 1, defport);
    if (!cfg->listen_addr)
      return -1;

    /* Validate option selection. */
    if (got_dest && (c->mode == LSN_SOCKS_CLIENT)) {
      log_warn("obfs2: You can't be on socks mode and have --dest.");
      return -1;
    }

    if (!got_dest && (c->mode != LSN_SOCKS_CLIENT)) {
      log_warn("obfs2: client/server mode needs --dest.");
      return -1;
    }

    log_debug("obfs2: Parsed options nicely!");

    return 0;
}


/** Return true iff the OBFUSCATE_SEED_LENGTH-byte seed in 'seed' is nonzero */
static inline int
seed_nonzero(const uchar *seed)
{
  static const uchar OBFUSCATE_ZERO_SEED[OBFUSCATE_SEED_LENGTH] = {0};
  return memcmp(seed, OBFUSCATE_ZERO_SEED, OBFUSCATE_SEED_LENGTH) != 0;
}

/** Return true iff the SHARED_SECRET_LENGTH-byte seed in 'seed' is nonzero */
static inline int
shared_seed_nonzero(const uchar *seed)
{
  static const uchar SHARED_ZERO_SEED[SHARED_SECRET_LENGTH] = {0};
  return memcmp(seed, SHARED_ZERO_SEED, SHARED_SECRET_LENGTH) != 0;
}

/*
   This function parses 'options' and fills the protocol parameters
   structure 'params'.

   Returns 0 on success, -1 on fail.
*/
static config_t *
obfs2_config_create(int n_options, const char *const *options)
{
  obfs2_config_t *cfg = xzalloc(sizeof(obfs2_config_t));
  config_t *c = upcast_config(cfg);
  c->vtable = &p_obfs2_vtable;

  if (parse_and_set_options(n_options, options, c) == 0)
    return c;

  config_free(c);
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
  return NULL;
}

/**
   Frees obfs2 parameters 'p'
 */
static void
obfs2_config_free(config_t *c)
{
  obfs2_config_t *cfg = downcast_config(c);
  if (cfg->listen_addr)
    evutil_freeaddrinfo(cfg->listen_addr);
  if (cfg->target_addr)
    evutil_freeaddrinfo(cfg->target_addr);
  /* wipe out keys */
  memset(cfg, 0x99, sizeof(obfs2_config_t));
  free(cfg);
}

/** Retrieve the 'n'th set of listen addresses for this configuration. */
static struct evutil_addrinfo *
obfs2_config_get_listen_addrs(config_t *cfg, size_t n)
{
  if (n > 0)
    return 0;
  return downcast_config(cfg)->listen_addr;
}

/* Retrieve the target address for this configuration. */
static struct evutil_addrinfo *
obfs2_config_get_target_addr(config_t *cfg)
{
  return downcast_config(cfg)->target_addr;
}

/* Create a circuit object. */
static circuit_t *
obfs2_circuit_create(config_t *c)
{
  circuit_t *ckt = upcast_circuit(xzalloc(sizeof(obfs2_circuit_t)));
  ckt->cfg = c;
  return ckt;
}

/* Destroy a circuit object. */
static void
obfs2_circuit_free(circuit_t *c)
{
  free(downcast_circuit(c));
}

/**
   Derive and return padding key of type 'keytype' from the seeds
   currently set in state 's'.
*/
static crypt_t *
derive_padding_key(void *s, const uchar *seed,
                   const char *keytype)
{
  obfs2_conn_t *state = s;

  crypt_t *cryptstate;
  uchar buf[SHA256_LENGTH];
  digest_t *c = digest_new();

  digest_update(c, (uchar*)keytype, strlen(keytype));
  if (seed_nonzero(seed))
    digest_update(c, seed, OBFUSCATE_SEED_LENGTH);
  if (shared_seed_nonzero(state->secret_seed))
    digest_update(c, state->secret_seed, OBFUSCATE_SEED_LENGTH);
  digest_update(c, (uchar*)keytype, strlen(keytype));
  digest_getdigest(c, buf, sizeof(buf));
  digest_free(c);

  if (shared_seed_nonzero(state->secret_seed)) {
    digest_t *d;
    int i;
    for (i=0; i < OBFUSCATE_HASH_ITERATIONS; i++) {
      d = digest_new();
      digest_update(d, buf, sizeof(buf));
      digest_getdigest(d, buf, sizeof(buf));
      digest_free(d);
    }
  }

  cryptstate = crypt_new(buf, 16);
  crypt_set_iv(cryptstate, buf+16, 16);
  memset(buf, 0, 16);
  return cryptstate;
}

/**
   This is called everytime we get a connection for the obfs2
   protocol.
*/
static conn_t *
obfs2_conn_create(config_t *c)
{
  obfs2_config_t *cfg = downcast_config(c);
  obfs2_conn_t *conn = xzalloc(sizeof(obfs2_conn_t));
  uchar *seed;
  const char *send_pad_type;

  conn->super.cfg = c;
  conn->state = ST_WAIT_FOR_KEY;
  conn->we_are_initiator = (cfg->super.mode != LSN_SIMPLE_SERVER);
  if (conn->we_are_initiator) {
    send_pad_type = INITIATOR_PAD_TYPE;
    seed = conn->initiator_seed;
  } else {
    send_pad_type = RESPONDER_PAD_TYPE;
    seed = conn->responder_seed;
  }

  /* Generate our seed */
  memcpy(conn->secret_seed, cfg->shared_secret, SHARED_SECRET_LENGTH);

  if (random_bytes(seed, OBFUSCATE_SEED_LENGTH) < 0) {
    free(conn);
    return NULL;
  }

  /* Derive the key for what we're sending */
  conn->send_padding_crypto = derive_padding_key(conn, seed, send_pad_type);
  return upcast_conn(conn);
}

/**
    Frees obfs2 state 's'
*/
static void
obfs2_conn_free(conn_t *s)
{
  obfs2_conn_t *state = downcast_conn(s);
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
  memset(state, 0x0a, sizeof(obfs2_conn_t));
  free(state);
}


/**
   Write the initial protocol setup and padding message for state 's' to
   the evbuffer 'buf'.  Return 0 on success, -1 on failure.
 */
static int
obfs2_handshake(conn_t *s)
{
  obfs2_conn_t *state = downcast_conn(s);
  struct evbuffer *buf = conn_get_outbound(s);

  uint32_t magic = htonl(OBFUSCATE_MAGIC_VALUE), plength, send_plength;
  uchar msg[OBFUSCATE_MAX_PADDING + OBFUSCATE_SEED_LENGTH + 8];
  const uchar *seed;

  /* We're going to send:
      SEED | E_PAD_KEY( UINT32(MAGIC_VALUE) | UINT32(PADLEN) | WR(PADLEN) )
  */

  obfs_assert(sizeof(magic) == 4);

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

  log_debug("obfs2_handshake: %s queued %lu bytes",
            state->we_are_initiator ? "initiator" : "responder",
            (unsigned long)evbuffer_get_length(buf));

  return 0;
}

/**
   Helper: encrypt every byte from 'source' using the key in 'crypto',
   and write those bytes onto 'dest'.  Return 0 on success, -1 on failure.
 */
static int
obfs2_crypt_and_transmit(crypt_t *crypto,
                         struct evbuffer *source, struct evbuffer *dest)
{
  uchar data[1024];
  while (1) {
    int n = evbuffer_remove(source, data, 1024);
    if (n <= 0)
      return 0;
    stream_crypt(crypto, data, n);
    evbuffer_add(dest, data, n);
    log_debug("%s: Processed %d bytes.", __func__, n);
  }
}

/**
   Called when data arrives from the user side and we want to send the
   obfuscated version.  Copies and obfuscates data from 'source' into 'dest'
   using the state in 'state'.  Returns 0 on success, -1 on failure.
 */
static int
obfs2_send(conn_t *s, struct evbuffer *source)
{
  obfs2_conn_t *state = downcast_conn(s);
  struct evbuffer *dest = conn_get_outbound(s);

  if (state->send_crypto) {
    /* First of all, send any data that we've been waiting to send. */
    if (state->pending_data_to_send) {
      log_debug("%s: transmitting %lu bytes previously queued.", __func__,
                (unsigned long)evbuffer_get_length(state->pending_data_to_send));
      obfs2_crypt_and_transmit(state->send_crypto,
                               state->pending_data_to_send,
                               dest);
      evbuffer_free(state->pending_data_to_send);
      state->pending_data_to_send = NULL;
    }
    /* Our crypto is set up; just relay the bytes */
    if (evbuffer_get_length(source)) {
      log_debug("%s: transmitting %lu bytes.", __func__,
                (unsigned long)evbuffer_get_length(source));
    }
    return obfs2_crypt_and_transmit(state->send_crypto, source, dest);
  } else {
    /* Our crypto isn't set up yet, we'll have to queue the data */
    if (evbuffer_get_length(source)) {
      log_debug("%s: handshake incomplete, queueing %lu bytes.", __func__,
                (unsigned long)evbuffer_get_length(source));
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
   Derive and return key of type 'keytype' from the seeds currently set in
   'state'.
 */
static crypt_t *
derive_key(void *s, const char *keytype)
{
  obfs2_conn_t *state = s;
  crypt_t *cryptstate;
  uchar buf[SHA256_LENGTH];
  digest_t *c = digest_new();

  digest_update(c, (uchar*)keytype, strlen(keytype));
  if (seed_nonzero(state->initiator_seed))
    digest_update(c, state->initiator_seed, OBFUSCATE_SEED_LENGTH);
  if (seed_nonzero(state->responder_seed))
    digest_update(c, state->responder_seed, OBFUSCATE_SEED_LENGTH);
  if (shared_seed_nonzero(state->secret_seed))
    digest_update(c, state->secret_seed, SHARED_SECRET_LENGTH);
  digest_update(c, (uchar*)keytype, strlen(keytype));
  digest_getdigest(c, buf, sizeof(buf));

  if (shared_seed_nonzero(state->secret_seed)) {
    digest_t *d;
    int i;
    for (i=0; i < OBFUSCATE_HASH_ITERATIONS; i++) {
      d = digest_new();
      digest_update(d, buf, sizeof(buf));
      digest_getdigest(d, buf, sizeof(buf));
      digest_free(d);
    }
  }

  cryptstate = crypt_new(buf, 16);
  crypt_set_iv(cryptstate, buf+16, 16);
  memset(buf, 0, sizeof(buf));
  digest_free(c);
  return cryptstate;
}

/**
   Helper: called after reciving our partner's setup message.  Initializes all
   keys.  Returns 0 on success, -1 on failure.
 */
static void
init_crypto(void *s)
{
  obfs2_conn_t *state = s;

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
obfs2_recv(conn_t *s, struct evbuffer *dest)
{
  obfs2_conn_t *state = downcast_conn(s);
  struct evbuffer *source = conn_get_inbound(s);

  if (state->state == ST_WAIT_FOR_KEY) {
    /* We're waiting for the first OBFUSCATE_SEED_LENGTH+8 bytes to show up
     * so we can learn the partner's seed and padding length */
    uchar buf[OBFUSCATE_SEED_LENGTH+8], *other_seed;
    uint32_t magic, plength;
    if (evbuffer_get_length(source) < OBFUSCATE_SEED_LENGTH+8) {
      log_debug("%s: waiting for key, %lu/%u bytes so far",
                __func__, (unsigned long)evbuffer_get_length(source),
                OBFUSCATE_SEED_LENGTH+8);
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
    init_crypto(state);

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
    log_debug("%s: received key, expecting %d bytes of padding",
              __func__, plength);
  }

  /* If we're still looking for padding, start pulling off bytes and
     discarding them. */
  while (state->padding_left_to_read) {
    int n = state->padding_left_to_read;
    size_t sourcelen = evbuffer_get_length(source);
    if (!sourcelen)
      return RECV_INCOMPLETE;
    if ((size_t) n > sourcelen)
      n = sourcelen;
    evbuffer_drain(source, n);
    state->padding_left_to_read -= n;
    log_debug("%s: consumed %d bytes padding, %d still to come",
              __func__, n, state->padding_left_to_read);
  }

  /* Okay; now we're definitely open.  Process whatever data we have. */
  state->state = ST_OPEN;

  log_debug("%s: Processing %lu bytes application data",
            __func__, (unsigned long)evbuffer_get_length(source));
  obfs2_crypt_and_transmit(state->recv_crypto, source, dest);

  /* If we have pending data to send, transmit it now. */
  if (state->pending_data_to_send)
    return RECV_SEND_PENDING;

  return RECV_GOOD;
}
