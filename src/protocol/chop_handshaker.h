/* Copyright 2013, Tor Project Inc.
 * See LICENSE for other credits and copying information
 *
 * AUTHOR:
 *    Vmon (vmon@riseup.net): August 2013: initial version
 */

#ifndef CHOP_HANDSHAKER_H
#define CHOP_HANDSHAKER_H

#include "rng.h"

struct ecb_encryptor;
struct ecb_decryptor;
struct gcm_encryptor;

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
const size_t CIRCUIT_ID_LEN = sizeof(uint32_t);
const size_t PADDING_LEN = 12;

class ChopHandshaker
{

public:
  uint32_t circuit_id;
   
  ChopHandshake(conn_circuit_id = 0) : circuit_id(conn_circuit_id) {}

  /** 
     Generates the handshake for a connection whose circuit_id is already
     set

     @param handshake: empty buffer of size HANDSHAKE_LEN will contains the handshake
     @param ec: the block cipher to encrypt the circuit_id
   */
  void genenrate(unit32_t* handshake, ecb_encryptor& ec)
  {
    unit32_t id_cat_padding[CIRCUIT_ID_LEN + PADDING_LEN];
    id_cat_padding[0] = circuit_id;
    rng_bytes((uint8_t*)(id_cat_padding + 1), sizeof(uint32_t) * PADDING_LEN);
    ec.encrypt(handshake, id_cat_padding);
    sha1((uint8_t*)(id_cat_padding), (CIRCUIT_ID_LEN + PADDING_LEN) * sizeof(uint32_t),(uint8_t*)(handshake + CIRCUIT_ID_LEN + PADDING_LEN));
    
  }

  /**
     Verifies the handshake and extract the circuit id and store
     it in the class member circuit_id

     @return false in case verification fails 
  */
  bool verify_and_extract(unit32_t* handshake, ecb_decryptor& dc)
  {
    unit_8 id_cat_padding[CIRCUIT_ID_LEN + PADDING_LEN];
    uint_8 verify_buf[SHA1_DIGEST_LENGTH];

    dc.encrypt(id_cat_padding,handshake);
    sha1((uint8_t*)(id_cat_padding), (CIRCUIT_ID_LEN + PADDING_LEN) * sizeof(uint32_t), verify_buf);
    if (memcmp(verify_buf, handshake + (CIRCUIT_ID_LEN + PADDING_LEN) * sizeof(uint32_t), SHA1_DIGEST_LENGTH))
      return fail; //not a valid handshake

    circuit_id = id_cat_padding[0];
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
