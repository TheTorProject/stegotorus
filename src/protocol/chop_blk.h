/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef CHOP_BLK_H
#define CHOP_BLK_H

#include "crypt.h"
#include <event2/buffer.h>

namespace chop_blk
{

/* Packets on the wire have a 16-byte header, consisting of a 32-bit
   sequence number, two 16-bit length fields ("D" and "P"), an 8-bit
   opcode ("F"), and a 56-bit check field.  All numbers in this header
   are serialized in network byte order.

   | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
   |Sequence Number|   D   |   P   | F |           Check           |

   The header is encrypted with AES in ECB mode: this is safe because
   the header is exactly one AES block long, the sequence number is
   never repeated, the header-encryption key is not used for anything
   else, and the high 24 bits of the sequence number, plus the check
   field, constitute an 80-bit MAC.  The receiver maintains a
   256-element sliding window of acceptable sequence numbers, which
   begins one after the highest sequence number so far _processed_
   (not received).  If the sequence number is outside this window, or
   the check field is not all-bits-zero, the packet is discarded.  An
   attacker's odds of being able to manipulate the D, P, or F fields
   or the low bits of the sequence number are therefore less than one
   in 2^80.  Unlike TCP, our sequence numbers always start at zero on
   a new (or freshly rekeyed) circuit, and increment by one per
   _block_, not per byte of data.  Furthermore, they do not wrap: a
   rekeying cycle (which resets the sequence number) is required to
   occur before the highest-received sequence number reaches 2^32.

   Following the header are two variable-length payload sections,
   "data" and "padding", whose length in bytes are given by the D and
   P fields, respectively.  These sections are encrypted, using a
   different key, with AES in GCM mode.  The *encrypted* packet header
   doubles as the GCM nonce.  The semantics of the "data" section's
   contents, if any, are defined by the opcode F.  The "padding"
   section SHOULD be filled with zeroes by the sender; regardless, its
   contents MUST be ignored by the receiver.  Following these sections
   is a 16-byte GCM authentication tag, computed over the data and
   padding sections only, NOT the message header.  */

const size_t HEADER_LEN = 16;
const size_t TRAILER_LEN = 16;
const size_t SECTION_LEN = UINT16_MAX;
const size_t MIN_BLOCK_SIZE = HEADER_LEN + TRAILER_LEN;
const size_t MAX_BLOCK_SIZE = MIN_BLOCK_SIZE + SECTION_LEN*2;

const size_t HANDSHAKE_LEN = sizeof(uint32_t);

enum opcode_t
{
  op_DAT = 0,       // Pass data section along to upstream
  op_FIN = 1,       // No further transmissions (pass data along if any)
  op_RST = 2,       // Protocol error, close circuit now
  op_RESERVED0 = 3, // 3 -- 127 reserved for future definition
  op_STEG0 = 128,   // 128 -- 255 reserved for steganography modules
  op_LAST = 255
};

/**
 * Produce a human-readable codename for opcode O.
 * FALLBACKBUF is used for opcodes that have no official assignment.
 * Will either return FALLBACKBUF or a pointer to a string constant.
 */
extern const char *opname(opcode_t o, char fallbackbuf[4]);

class header
{
  uint8_t clear[16];
  uint8_t ciphr[16];

public:
  header(uint32_t s, uint16_t d, uint16_t p, opcode_t f, ecb_encryptor &ec)
  {
    if (f > op_LAST || (f >= op_RESERVED0 && f < op_STEG0)) {
      memset(clear, 0xFF, sizeof clear); // invalid!
      memset(ciphr, 0xFF, sizeof ciphr);
      return;
    }

    // sequence number
    clear[0] = (s >> 24) & 0xFF;
    clear[1] = (s >> 16) & 0xFF;
    clear[2] = (s >>  8) & 0xFF;
    clear[3] = (s      ) & 0xFF;

    // D field
    clear[4] = (d >>  8) & 0xFF;
    clear[5] = (d      ) & 0xFF;

    // P field
    clear[6] = (p >>  8) & 0xFF;
    clear[7] = (p      ) & 0xFF;

    // F field
    clear[8] = uint8_t(f);

    // Check field
    memset(clear + 9, 0, 7);

    ec.encrypt(ciphr, clear);
  }

  header(evbuffer *buf, ecb_decryptor &dc)
  {
    if (evbuffer_copyout(buf, ciphr, sizeof ciphr) != sizeof ciphr) {
      memset(clear, 0xFF, sizeof clear);
      memset(ciphr, 0xFF, sizeof ciphr);
      return;
    }
    dc.decrypt(clear, ciphr);
  }

  uint32_t seqno() const
  {
    return ((uint32_t(clear[0]) << 24) |
            (uint32_t(clear[1]) << 16) |
            (uint32_t(clear[2]) <<  8) |
            (uint32_t(clear[3])      ));

  }

  size_t dlen() const
  {
    return ((uint16_t(clear[4]) << 8) |
            (uint16_t(clear[5])     ));
  }

  size_t plen() const
  {
    return ((uint16_t(clear[6]) << 8) |
            (uint16_t(clear[7])     ));
  }

  size_t total_len() const
  {
    return HEADER_LEN + TRAILER_LEN + dlen() + plen();
  }

  opcode_t opcode() const
  {
    return opcode_t(clear[8]);
  }

  bool valid(uint64_t window) const
  {
    // This check must run in constant time.
    uint8_t ck = (clear[ 9] | clear[10] | clear[11] | clear[12] |
                  clear[13] | clear[14] | clear[15]);
    uint32_t delta = seqno() - window;
    ck |= !!(delta & ~uint32_t(0xFF));
    return !ck;
  }

  const uint8_t *nonce() const
  {
    return ciphr;
  }

  const uint8_t *cleartext() const
  {
    return clear;
  }
};


/* Most of a block's header information is processed before it reaches
   the reassembly queue; the only things the queue needs to record are
   the sequence number (which is stored implictly), the opcode, and an
   evbuffer holding the data section.  Zero-data blocks still get an
   evbuffer, for simplicity's sake: a reassembly queue element holds a
   received block if and only if its data pointer is non-null.

   The reassembly queue is a 256-element circular buffer of
   'reassembly_elt' structs.  This corresponds to the 256-element
   sliding window of sequence numbers which may legitimately be
   received at any time.  */

struct reassembly_elt
{
  evbuffer *data;
  opcode_t op;
};

class reassembly_queue
{
  reassembly_elt cbuf[256];
  uint32_t next_to_process;

  reassembly_queue(const reassembly_queue&) DELETE_METHOD;
  reassembly_queue& operator=(const reassembly_queue&) DELETE_METHOD;

public:
  reassembly_queue();
  ~reassembly_queue();

  /**
   * Remove the next block to be processed from the reassembly queue
   * and return it.  If we are out of blocks or the next block to
   * process has not yet arrived, return an empty reassembly_elt.
   * Caller is responsible for freeing the evbuffer in the
   * reassembly_elt, if any.
   */
  reassembly_elt remove_next();

  /**
   * Insert a block into the reassembly queue at sequence number
   * SEQNO, with opcode OP and data section DATA.  Returns true if the
   * block was successfully added to the queue, false if it is either
   * outside the acceptable window or duplicates a block already on
   * the queue (both of these cases indicate protocol errors).
   * DATA is consumed no matter what the return value is.
   */
  bool insert(uint32_t seqno, opcode_t op, evbuffer *data, conn_t *conn);

  /**
   * Return the current lowest acceptable sequence number in the
   * receive window. This is the value to be passed to
   * block_header::valid().
   */
  uint32_t window() const { return next_to_process; }

  /**
   * Reset the expected next sequence number to zero.  The queue must
   * be empty.  This is done as the last step of a rekeying cycle.
   */
  void reset();
};

} // namespace chop_blk

#endif /* chop_blk.h */

// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
