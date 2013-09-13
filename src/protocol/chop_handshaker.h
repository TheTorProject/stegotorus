/* Copyright 2013, Tor Project Inc.
 * See LICENSE for other credits and copying information
 *
 * AUTHOR:
 *    Vmon (vmon@riseup.net): August 2013: initial version
 */

#ifndef CHOP_HANDSHAKER_H
#define CHOP_HANDSHAKER_H

#include <openssl/sha.h>

#include "rng.h"

/* The handshake generator and reciever class for chop protocol, 
   this is a simplest implementation for a verifiable handshake to 
   resiste active probing and letting normal traffic by pass 
   stegotorus.

   the idea is that the one can inherit from this class and 
   make a more complicated handshake

   Each is 16bit word:
   | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
   | Enc_ecb(Circuit ID + Padding) | SHA-1(Circuit ID + Padding)   |

   It is not the most secure header more secure header out-there
   TODO: Make a secure header with Elligator algorithm

  */

const size_t HANDSHAKE_LEN = 32;//sizeof(uint32_t);
const size_t NO_ENCRYPTED_WORDS = 4;
const size_t CIRCUIT_ID_LEN = sizeof(uint32_t);
const size_t PADDING_LEN = 12;
const size_t HANDSHAKE_DIGEST_LENGTH = HANDSHAKE_LEN - CIRCUIT_ID_LEN - PADDING_LEN;

class ChopHandshaker
{

public:
  uint32_t circuit_id;
   
  ChopHandshaker(uint32_t conn_circuit_id = 0) : circuit_id(conn_circuit_id) {};

  /** 
     Generates the handshake for a connection whose circuit_id is already
     seti

     @param handshake: empty buffer of size HANDSHAKE_LEN will contains the handshake
     @param ec: the block cipher to encrypt the circuit_id
   */
  void generate(uint8_t* handshake, ecb_encryptor& ec)
  {
    uint32_t id_cat_padding[NO_ENCRYPTED_WORDS];
    uint8_t digest_buffer[SHA256_DIGEST_LENGTH];
    log_debug("circ id to send %u", circuit_id);
    id_cat_padding[0] = circuit_id;
    rng_bytes((uint8_t*)(id_cat_padding + 1),  PADDING_LEN);
    ec.encrypt(handshake, (const uint8_t*)id_cat_padding);
    sha256((uint8_t*)(id_cat_padding), CIRCUIT_ID_LEN + PADDING_LEN, digest_buffer);
    memcpy((uint8_t*)(handshake + CIRCUIT_ID_LEN + PADDING_LEN), digest_buffer, HANDSHAKE_DIGEST_LENGTH);
    
  }

  /**
     Verifies the handshake and extract the circuit id and store
     it in the class member circuit_id

     @return false in case verification fails 
  */
  bool verify_and_extract(uint8_t* handshake, ecb_decryptor& dc)
  {
    uint32_t id_cat_padding[NO_ENCRYPTED_WORDS];
    uint8_t verify_buf[SHA256_DIGEST_LENGTH];

    dc.decrypt((uint8_t*)id_cat_padding,handshake);
    sha256((uint8_t*)id_cat_padding, CIRCUIT_ID_LEN + PADDING_LEN, verify_buf);
    if (memcmp(verify_buf, handshake + (CIRCUIT_ID_LEN + PADDING_LEN), HANDSHAKE_DIGEST_LENGTH))
      return false; //not a valid handshake

    circuit_id = id_cat_padding[0];
    log_debug("retrieved circ id %u", circuit_id);
    return true;
    
  }

};

#endif /* chop_handshaker.h */

// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
