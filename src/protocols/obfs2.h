/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_OBFS2_H
#define PROTOCOL_OBFS2_H

#include "crypt.h"
#include "connections.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========
   These definitions are not part of the obfs2_protocol interface.
   They're exposed here so that the unit tests can use them.
   ==========
*/

/* our own, since we break brl's spec */
#define OBFUSCATE_MAGIC_VALUE        0x2BF5CA7E
#define OBFUSCATE_SEED_LENGTH        16
#define OBFUSCATE_MAX_PADDING        8192
#define OBFUSCATE_HASH_ITERATIONS     100000

#define INITIATOR_PAD_TYPE "Initiator obfuscation padding"
#define RESPONDER_PAD_TYPE "Responder obfuscation padding"
#define INITIATOR_SEND_TYPE "Initiator obfuscated data"
#define RESPONDER_SEND_TYPE "Responder obfuscated data"

#define SHARED_SECRET_LENGTH SHA256_LENGTH

typedef struct obfs2_config_t {
  config_t super;
  struct evutil_addrinfo *listen_addr;
  struct evutil_addrinfo *target_addr;
  uint8_t shared_secret[SHARED_SECRET_LENGTH];
} obfs2_config_t;

typedef struct obfs2_conn_t {
  conn_t super;

  /** Current protocol state.  We start out waiting for key information.  Then
      we have a key and wait for padding to arrive.  Finally, we are sending
      and receiving bytes on the connection.  */
  enum {
    ST_WAIT_FOR_KEY,
    ST_WAIT_FOR_PADDING,
    ST_OPEN
  } state;
  /** Random seed we generated for this stream */
  uint8_t initiator_seed[OBFUSCATE_SEED_LENGTH];
  /** Random seed the other side generated for this stream */
  uint8_t responder_seed[OBFUSCATE_SEED_LENGTH];
  /** Shared secret seed value. */
  uint8_t secret_seed[SHARED_SECRET_LENGTH];
  /** True iff we opened this connection */
  int we_are_initiator;
  /** True if we need to send pending data before we can close the connection */
  int close_after_send;

  /** key used to encrypt outgoing data */
  crypt_t *send_crypto;
  /** key used to encrypt outgoing padding */
  crypt_t *send_padding_crypto;
  /** key used to decrypt incoming data */
  crypt_t *recv_crypto;
  /** key used to decrypt incoming padding */
  crypt_t *recv_padding_crypto;

  /** Buffer full of data we'll send once the handshake is done. */
  struct evbuffer *pending_data_to_send;

  /** Number of padding bytes to read before we get to real data */
  int padding_left_to_read;
} obfs2_conn_t;

typedef struct obfs2_circuit_t {
  circuit_t super;
  conn_t *downstream;
} obfs2_circuit_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
