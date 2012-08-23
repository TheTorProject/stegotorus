/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef CHOP_BLK_H
#define CHOP_BLK_H

#include <tr1/unordered_set>

class ecb_encryptor;
class ecb_decryptor;

namespace chop_blk
{

/* Packets on the wire have a 16-byte header, consisting of a 32-bit
   sequence number, two 16-bit length fields ("D" and "P"), an 8-bit
   opcode ("F"), an 8-bit retransmit count ("R"), and a 48-bit check
   field.  All numbers in this header are serialized in network byte
   order.

   | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
   |Sequence Number|   D   |   P   | F | R |       Check           |

   The header is encrypted with AES in ECB mode: this is safe because
   the header is exactly one AES block long, the sequence number +
   retransmit count is never repeated, the header-encryption key is
   not used for anything else, and the high 24 bits of the sequence
   number, plus the check field, constitute an 72-bit MAC.  The
   receiver maintains a 256-element sliding window of acceptable
   sequence numbers, which begins one after the highest sequence
   number so far _processed_ (not received).  If the sequence number
   is outside this window, or the check field is not all-bits-zero,
   the packet is discarded.  An attacker's odds of being able to
   manipulate the D, P, F, or R fields or the low bits of the sequence
   number are therefore less than one in 2^72.  Unlike TCP, our
   sequence numbers always start at zero on a new (or freshly rekeyed)
   circuit, and increment by one per _block_, not per byte of data.
   Furthermore, they do not wrap: a rekeying cycle (which resets the
   sequence number) is required to occur before the highest-received
   sequence number reaches 2^32.

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
  op_ACK = 3,       // Acknowledge data received
  op_RESERVED0 = 4, // 4 -- 127 reserved for future definition
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
  header()
  {
    memset(clear, 0xFF, sizeof clear);
    memset(ciphr, 0xFF, sizeof ciphr);
  }

  header(uint32_t s, uint16_t d, uint16_t p, opcode_t f, ecb_encryptor &ec);
  header(evbuffer *buf, ecb_decryptor &dc);

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

  uint8_t rcount() const
  {
    return clear[9];
  }

  // Returns false if incrementing the retransmit count has caused it
  // to wrap around to zero.  If this happens, we have to stop trying
  // to retransmit the block.
  bool prepare_retransmit(uint16_t new_plen, ecb_encryptor &ec);

  bool valid(uint64_t window) const
  {
    // This check must run in constant time.
    uint8_t ck = (clear[10] | clear[11] | clear[12] |
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

/**
 * An ACK payload begins with a 32-bit number (network byte order as
 * usual) which is the highest sequence number so far processed
 * (henceforth HSN).  After that are up to 32 octets of bitmask, laid
 * out in *little*-endian order, corresponding to the 256-element
 * block receive window.  Bits set in this bitmask indicate blocks
 * past the HSN that have in fact been received.  If the bitmask is
 * shorter than 32 octets it is implicitly zero-filled out to its
 * maximum size.  By construction, the lowest bit in the bitmask will
 * always be zero, because if block HSN+1 had been received, HSN would
 * be higher; but it is transmitted anyway.
 */
class ack_payload
{
  uint32_t hsn_;
  uint32_t maxusedbyte;
  uint8_t  window[32];

public:
  /**
   * Create a new ack_payload object, specifying its HSN.  For the
   * sake of testing, this *can* be used to create an explicitly
   * invalid ack_payload (by passing uint32_t(-1)), unlike set_hsn()
   * below.
   */
  ack_payload(uint32_t h) : hsn_(h), maxusedbyte(0)
  { memset(window, 0, sizeof window); }

  /**
   * Decode an ack_payload from the wire format.  HFLOOR is a lower
   * bound on the expected HSN.  Before doing anything else with the
   * object constructed, you must check whether valid() returns true;
   * all the other functions will trigger a fatal assertion if called
   * on an invalid ack_payload.
   */
  ack_payload(evbuffer *wire, uint32_t hfloor);

  /**
   * Serialize this ack_payload to the wire format.
   */
  evbuffer *serialize() const;

  /**
   * Report whether a wire-decoded ack_payload is valid.
   */
  bool valid() const { return hsn_ != uint32_t(-1); }

  /**
   * Returns the HSN for this ack_payload object.
   */
  uint32_t hsn() const
  {
    log_assert(valid());
    return hsn_;
  }

  /**
   * Change the HSN for this ack_payload object.
   * This cannot be used to make an ack_payload invalid.
   */
  void set_hsn(uint32_t h)
  {
    log_assert(valid() && h != uint32_t(-1));
    hsn_ = h;
  }

  /**
   * Report whether the block with sequence number SEQ has been successfully
   * received, according to the data in this ack_payload.
   */
  bool block_received(uint32_t seq) const
  {
    log_assert(valid());

    if (seq <= hsn_)
      return true;

    uint32_t delta = (seq - hsn_) - 1;
    if (delta >= 256)
      return false;

    return window[delta / 8] & (1 << (delta % 8));
  }

  /**
   * Mark the block with sequence number SEQ (which must be in the range
   * [hsn+1, hsn+256]) as having been received.
   */
  void set_block_received(uint32_t seq)
  {
    log_assert(valid());

    uint32_t delta = (seq - hsn_) - 1;
    log_assert(delta < 256);
    window[delta/8] |= (1 << (delta % 8));
    if (delta/8 + 1 > maxusedbyte)
      maxusedbyte = delta/8 + 1;
  }
};

/* The transmit queue holds blocks that we have transmitted at least
   once but do not know have been received.  It is a 256-element circular
   buffer of 'transmit_elt' structs, corresponding to the 256-element
   sliding window of sequence numbers which may legitimately be
   transmitted at any time.

   Once a block is on the transmit queue, its payload length cannot
   change, but it can be repadded if necessary.  Zero-data blocks
   still get an evbuffer, for simplicity's sake: a transmit queue
   element holds a pending block if and only if its data pointer is
   non-null. */

 struct transmit_elt
 {
   header hdr;
   evbuffer *data;

   transmit_elt() : hdr(), data(0) {}
 };

 class transmit_queue
 {
   transmit_elt cbuf[256];
   uint32_t last_fully_acked;
   uint32_t next_to_send;

   transmit_queue(const transmit_queue&) DELETE_METHOD;
   transmit_queue& operator=(const transmit_queue&) DELETE_METHOD;

 public:
   transmit_queue();
   ~transmit_queue();

   /**
    * Return the sequence number to use for the next block to be
    * transmitted.
    */
   uint32_t next_seqno() const { return next_to_send; }

   /**
    * True if the transmit queue is full, i.e. we cannot transmit
    * anything right now.  (This does not necessarily mean that all
    * 256 slots are occupied; selective acknowledgment may have
    * cleared some of them.)
    */
   bool full() const
   { return next_to_send - last_fully_acked > 255; }

   /**
    * True if we ought to rekey soon, i.e. the sequence number is in
    * danger of wrapping around.
    */
   bool should_rekey() const { return next_to_send >= (1U<<31); }

   /**
    * Push a block (defined by header HDR and data payload DATA) on
    * the end of the transmit queue, and immediately transmit it on
    * connection CONN.  May not be called when full() is true.  Can
    * fail: returns -1 for failure or 0 for success.  Regardless of
    * success or failure, consumes DATA.
    */
   int queue_and_send(header const& hdr, evbuffer *data, conn_t *conn);

   /**
    * Process an acknowledgment, advancing the last_fully_acked
    * counter and discarding blocks that have definitely been received
    * on the far side.  Returns -1 for failure or 0 for success:
    * failure indicates an ill-formed ack payload on the wire.
    * Consumes DATA regardless of success or failure.
    */
   int process_ack(evbuffer *data);

   /**
    * Retransmit as many blocks as possible given the present state of
    * the connections in DOWNSTREAMS.  No-op if there is nothing to be
    * retransmitted at this time.  Returns -1 if there was material to
    * retransmit but we did not manage to retransmit any of it, 0
    * otherwise.
    */
   int retransmit(std::tr1::unordered_set<conn_t *> &downstreams);
 };

/* Most of a block's header information is processed before it reaches
   the reassembly queue; the only things the queue needs to record are
   the sequence number (which is stored implictly), the opcode, and an
   evbuffer holding the data section.  Zero-data blocks still get an
   evbuffer, for simplicity's sake: a reassembly queue element holds a
   received block if and only if its data pointer is non-null.

   The reassembly queue is also a 256-element circular buffer, of
   'reassembly_elt' structs, following the same logic as the transmit
   queue. */

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

  /**
   * Generate an acknowledgment payload corresponding to the present
   * contents of the queue.
   */
  evbuffer *gen_ack() const;
};

} // namespace chop_blk

#endif /* chop_blk.h */

// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
