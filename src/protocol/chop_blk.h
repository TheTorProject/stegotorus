/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef CHOP_BLK_H
#define CHOP_BLK_H

#include <tr1/unordered_set>
#include <ostream>

struct ecb_encryptor;
struct ecb_decryptor;
struct gcm_encryptor;

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
   number are therefore less than one in 2^72.  (This is weak compared
   to our default security parameter of 2^128, but should be sufficient
   for the protection of this small amount of data.)

   Unlike TCP, our sequence numbers always start at zero on a new (or
   freshly rekeyed) circuit, and increment by one per _block_, not per
   byte of data.  Furthermore, they do not wrap: a rekeying cycle
   (which resets the sequence number) is required to occur before the
   highest-received sequence number reaches 2^32.

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
  op_XXX = 0,       // Permanently invalid opcode
  op_DAT = 1,       // Pass data section along to upstream
  op_FIN = 2,       // No further transmissions (pass data along if any)
  op_RST = 3,       // Protocol error, close circuit now
  op_ACK = 4,       // Acknowledge data received
  op_RESERVED0 = 5, // 4 -- 127 reserved for future definition
  op_STEG0 = 128,   // 128 -- 255 reserved for steganography modules
  op_STEG_FIN = 129,
  op_LAST = 255
};

/**
 * Produce a human-readable codename for opcode O.
 * FALLBACKBUF is used for opcodes that have no official assignment.
 * Will either return FALLBACKBUF or a pointer to a string constant.
 */
extern const char *opname(unsigned int o, char fallbackbuf[4]);

/**
 * Decode an ACK payload (directly from the wire format) and report
 * its contents in human-readable form.
 */
extern void debug_ack_contents(evbuffer *payload, std::ostream& os);

inline bool
opcode_valid(unsigned int o)
{
  return ((o > op_XXX && o < op_RESERVED0) ||
          (o >= op_STEG0 && o <= op_LAST));
}

class header
{
  uint32_t s;
  uint16_t d;
  uint16_t p;
  opcode_t f : 8;
  uint8_t  r;

public:
  header() : s(0), d(0), p(0), f(op_XXX), r(0) {}

  header(uint32_t s_, uint16_t d_, uint16_t p_, opcode_t f_)
    : s(0), d(0), p(0), f(op_XXX), r(0)
  {
    if (!opcode_valid(f_))
      return;
    s = s_;
    d = d_;
    p = p_;
    f = f_;
  }

  // Decode from wire format.  'ciphr' must point to 16 bytes of data.
  header(const uint8_t *ciphr, ecb_decryptor &dc, uint32_t window);

  // Encode to wire format.  'ciphr' must point to 16 bytes of space.
  void encode(uint8_t *ciphr, ecb_encryptor &ec) const;

  // Returns false if incrementing the retransmit count has caused it
  // to wrap around to zero.  If this happens, we have to stop trying
  // to retransmit the block.
  bool prepare_retransmit(uint16_t new_plen);

  // Accessors.
  uint32_t seqno()  const { return s; }
  size_t   dlen()   const { return d; }
  size_t   plen()   const { return p; }
  opcode_t opcode() const { return f; }
  uint8_t  rcount() const { return r; }

  size_t total_len() const
  {
    return HEADER_LEN + TRAILER_LEN + dlen() + plen();
  }

  bool valid() const
  {
    return f != op_XXX;
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
    if (delta >= 256)
      log_abort("seq %u too high (hsn %u)", seq, hsn_);

    window[delta/8] |= (1 << (delta % 8));
    if (delta/8 + 1 > maxusedbyte)
      maxusedbyte = delta/8 + 1;
  }

  /**
   * Print out the whole window array in hex format for debug
   * purpose
   */
  void log_info_window()
  {  
    char log_ack_stat[1024] = {};
    char curstat[] = "00";
    for (int i = 0; i < 32; i++) {
      sprintf(curstat, "%02x", window[i]);
      strcat(log_ack_stat, curstat);
    }
    
    log_info("ack status: %s hsn: %u", log_ack_stat, hsn_);
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
   uint32_t next_to_ack;
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
   { return next_to_send - next_to_ack > 255; }

   /**
    * True if we ought to rekey soon, i.e. the sequence number is in
    * danger of wrapping around.
    */
   bool should_rekey() const { return next_to_send >= 0x80000000u; }

   /**
    * Push a block on the end of the transmit queue.  The block has
    * opcode F, carries all of the data in DATA, and is padded with
    * PADDING bytes at the end.  Returns the sequence number of the
    * new block.  Must not be called when full() is true.
    */
   uint32_t enqueue(opcode_t f, evbuffer *data, uint16_t padding);

   /**
    * Encrypt the block with sequence number SEQNO and append it to
    * the evbuffer OUTPUT.  That block must have already been on the
    * transmit queue.  Optionally, change how much padding the block
    * has.  Returns 0 on success, -1 on failure.  Failure can occur,
    * among other reasons, if the block in question has been
    * retransmitted too many times.
    */
   int transmit(uint32_t seqno,
                evbuffer *output, ecb_encryptor &ec, gcm_encryptor &gc)
   {
     log_assert(seqno >= next_to_ack && seqno < next_to_send);
     transmit_elt &elt = cbuf[seqno & 0xFF];
     return transmit(elt, output, ec, gc);
   }
   int transmit(transmit_elt &elt,
                evbuffer *output, ecb_encryptor &ec, gcm_encryptor &gc);

   int retransmit(uint32_t seqno, uint16_t new_padding,
                  evbuffer *output, ecb_encryptor &ec, gcm_encryptor &gc)
   {
     log_assert(seqno >= next_to_ack && seqno < next_to_send);
     transmit_elt &elt = cbuf[seqno & 0xFF];
     return retransmit(elt, new_padding, output, ec, gc);
   }
   int retransmit(transmit_elt &elt, uint16_t new_padding,
                  evbuffer *output, ecb_encryptor &ec, gcm_encryptor &gc);

   /**
    * Process an acknowledgment, advancing the last_fully_acked
    * counter and discarding blocks that have definitely been received
    * on the far side.  Returns -1 for failure or 0 for success:
    * failure indicates an ill-formed ack payload on the wire.
    * Consumes DATA regardless of success or failure.
    */
   int process_ack(evbuffer *data);

   /**
    * Iteration over the transmit queue produces each block which has
    * been enqueued but not yet discarded by process_ack.  Used for
    * retransmission.
    */
   class iterator
   {
     transmit_queue *queue;
     uint32_t seqno;

   public:
     iterator() : queue(0), seqno(-1) {}
     iterator(transmit_queue *q, uint32_t s) : queue(q), seqno(s) {}

     bool operator==(const iterator& o)
     { return queue == o.queue && seqno == o.seqno; }
     bool operator!=(const iterator& o)
     { return queue != o.queue || seqno != o.seqno; }

     transmit_elt& operator*() { return queue->cbuf[seqno & 0xFF]; }
     iterator operator++()
     {
       do
         seqno++;
       while (seqno < queue->next_to_send && !queue->cbuf[seqno & 0xFF].data);
       return *this;
     }
     iterator operator++(int)
     {
       iterator clone(*this);
       ++*this;
       return clone;
     }
   };

   iterator begin() { return iterator(this, next_to_ack); }
   iterator end() { return iterator(this, next_to_send); }
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
  conn_t* conn;
};

class reassembly_queue
{
  reassembly_elt cbuf[256];
  uint32_t next_to_process;
  uint32_t count; // only a uint8_t is _necessary_, but that's a false
                  // economy; using a uint32_t means we don't have to
                  // worry about overflow at the upper limit, and the
                  // size of the class will be the same in either case

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
  bool insert(uint32_t seqno, opcode_t op, evbuffer *data);

  /**
   * Return the current lowest acceptable sequence number in the
   * receive window. This is the value to be passed to
   * block_header::valid().
   */
  uint32_t window() const { return next_to_process; }

  /**
   * True if the queue is completely empty.
   */
  bool empty() const { return count == 0; }

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
