
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <event2/buffer.h>

#include "crypt_protocol.h"
#include "crypt.h"

/* from brl's obfuscated-ssh standard. */
//#define OBFUSCATE_MAGIC_VALUE        0x0BF5CA7E

/* our own, since we break brl's spec */
#define OBFUSCATE_MAGIC_VALUE        0x2BF5CA7E
#define OBFUSCATE_SEED_LENGTH        16
#define OBFUSCATE_MAX_PADDING        8192

#define INITIATOR_PAD_TYPE "Initiator obfuscation padding"
#define RESPONDER_PAD_TYPE "Responder obfuscation padding"
#define INITIATOR_SEND_TYPE "Initiator obfuscated data"
#define RESPONDER_SEND_TYPE "Responder obfuscated data"

struct protocol_state_t {
  enum {
    ST_WAIT_FOR_KEY,
    ST_WAIT_FOR_PADDING,
    ST_OPEN,
  } state;
  char initiator_seed[OBFUSCATE_SEED_LENGTH];
  char responder_seed[OBFUSCATE_SEED_LENGTH];
  char secret_seed[OBFUSCATE_SEED_LENGTH];
  int we_are_initiator;
  int received_other_seed;

  crypt_state_t *send_crypto;
  crypt_state_t *send_padding_crypto;
  crypt_state_t *recv_crypto;
  crypt_state_t *recv_padding_crypto;

  struct evbuffer *pending_data_to_send;

  int padding_left_to_read;
};

const crypt_state_t *
derive_key(const char *keytype, protocol_state_t *state)
{
  crypt_state_t *cryptstate;
  char buf[32];
  SHA256_CTX c;
  SHA256_Init(&c);
  SHA256_Update(&c, keytype, strlen(keytype));
  if (state->initiator_seed)
    SHA256_Update(&c, state->initiator_seed, OBFUSCATE_SEED_LENGTH);
  if (state->responder_seed)
    SHA256_Update(&c, state->responder_seed, OBFUSCATE_SEED_LENGTH);
  if (state->secret_seed)
    SHA256_Update(&c, state->secret_seed, OBFUSCATE_SEED_LENGTH);
  SHA256_Update(&c, keytype, strlen(keytype));
  SHA256_Final(buf, &c);
  cryptstate = crypt_state_new(buf);
  memset(buf, 0, sizeof(buf));
  return cryptstate;
}

protocol_state_t *
new_protocol_state(int initiator)
{
  int r;
  protocol_state_t *state = calloc(1, sizeof(protocol_state_t));
  char *seed;
  const char *send_pad_type;

  if (!state)
    return NULL;
  state->we_are_initiator = initator;
  if (initiator) {
    send_pad_type = INITIATOR_PAD_TYPE;
    seed = state->initiator_seed;
  } else {
    send_pad_type = RESPONDER_PAD_TYPE;
    seed = state->responder_seed;
  }

  if (0 == RAND_bytes(seed, OBFUSCATE_SEED_LENGTH)) {
    free(state);
    return NULL;
  }

  if (NULL == (state->send_padding_crypto = derive_key(state, send_pad_type))
    free(state);
    return NULL;
  }

  return state;
}

int
proto_send_initial_mesage(protocol_state_t *state, struct evbuffer *buf)
{
  uint32_t magic = htonl(OBFUSCATE_MAGIC), plength, send_plength;
  char msg[OBFUSCATE_MAX_PADDING + OBFUSCATE_SEED_LENGTH + 8];
  const char *seed;

  assert(sizeof(magic) == 4);

  if (0==RAND_bytes(&plength, 4))
    return -1;

  plength %= OBFUSCATE_MAX_PADDING;
  send_plength = htonl(send_plength);

  if (state->we_are_initiator)
    seed = state->initiator_seed;
  else
    seed = state->responder_seed;
  memcpy(msg, seed, OBFUSCATE_SEED_LENGTH);
  memcpy(msg+OBFUSCATE_SEED_LENGTH, magic, 4);
  memcpy(msg+OBFUSCATE_SEED_LENGTH+4, send_plength, 4);
  if (0 == RAND_bytes(msg+OBFUSCATE_SEED_LENGTH+8, plength))
    return -1;

  stream_crypt(state->send_padding_crypto,
               msg+OBFUSCATE_SEED_LENGTH, 8+plength);

  evbuffer_add(buf, msg, OBFUSCATE_SEED_LENGTH+8+plength);
  return 0;
}

static int
crypt_and_transmit(crypt_state_t *crypto,
                   struct evbuffer *source, struct evbuffer *dest)
{
  char data[1024];
  while (1) {
    int n = evbuffer_remove(source, data, 1024);
    if (n <= 0)
      return 0;
    stream_crypt(crypto, data, n);
    evbuffer_add(dest, data, n);
  }
}

int
proto_send(protocol_state_t *state,
           struct evbuffer *source, struct evbuffer *dest)
{
  if (state->send_crypto) {
    return crypt_and_transmit(state->send_crypto, source, dest);
  } else {
    if (evbuffer_get_length(source)) {
      if (! state->pending_data_to_send) {
        state->pending_data_to_send = evbuffer_new();
      }
      evbuffer_add_buffer(state->pending_data_to_send, source);
    }
    return 0;
  }
}

static int
init_crypto(protocol_state_t *state)
{
  const char *send_keytype;
  const char *recv_keytype;
  const char *recv_pad_keytype;

  if (state->we_are_initiator) {
    send_keytype = INITIATOR_SEND_TYPE;
    recv_keytype = RESPONDER_SEND_TYPE;
    recv_pad_keytype = RESPONDER_PAD_TYPE;
  } else {
    send_keytype = RESPONDER_SEND_TYPE;
    recv_keytype = INITIATOR_SEND_TYPE;
    recv_pad_keytype = INITIATOR_PAD_TYPE;
  }

  state->send_crypto = derive_key(state, send_keytype);
  state->recv_crypto = derive_key(state, recv_keytype);
  state->recv_padding_crypto = derive_key(state, recv_pad_keytype);

  if (state->send_crypto && state->recv_crypto && state->recv_padding_crypto)
    return 0;
  else
    return -1;
}

/* x for "don't call again till you have x bytes".  0 for "all ok". -1 for
 * "fail, close" */
int
proto_recv(protocol_state_t *state, struct evbuffer *source,
           struct evbuffer *dest)
{
  if (state->state == ST_WAIT_FOR_KEY) {
    char buf[OBFUSCATE_SEED_LENGTH+8], *other_seed;
    uint32_t magic, plength;
    if (evbuffer_get_length(source) < OBFUSCATE_SEED_LENGTH+8)
      return OBFUSCATE_SEED_LENGTH+8;
    evbuffer_remove(source, buf, OBFUSCATE_STATE_LENGTH+8);

    if (state->we_are_initiator)
      other_seed = state->responder_seed;
    else
      other_seed = state->initiator_seed;

    memcpy(other_seed, buf, OBFUSCATED_SEED_LENGTH);

    if (init_crypto(state) < 0)
      return -1;

    stream_crypt(state->recv_padding_crypto, buf+OBFUSCATED_SEED_LENGTH, 8);
    memcpy(magic, buf+OBFUSCATED_SEED_LENGTH, 4);
    memcpy(plength, buf+OBFUSCATED_SEED_LENGTH+4, 4);
    magic = ntohl(magic);
    plength = ntohl(plength);
    if (magic != OBFUSCATE_MAGIC_VALUE)
      return -1;
    if (plength > OBFUSCATE_MAX_PADDING)
      return -1;

    if (state->pending_data_to_send) {
      crypt_and_transmit(state->send_crypto, state->pending_data_to_send, dest);
      evbuffer_free(state->pending_data_to_send);
      state->pending_data_to_send = NULL;
    }

    state->padding_left_to_read = plength;
    state->state = ST_WAIT_FOR_PADDING;
  }

  while (state->padding_left_to_read) {
    int n = state->padding_left_to_read;
    size_t sourcelen = evbuffer_get_length(source);
    if (!sourcelen)
      return n;
    if ((size_t) n > evbuffer_get_length(source))
      n = evbuffer_get_length(source);
    evbuffer_drain(source, n);
    state->padding_left_to_read -= n;
  }
  state->state = ST_OPEN;

  return crypt_and_transmit(state->recv_crypto, source, dest);
}

