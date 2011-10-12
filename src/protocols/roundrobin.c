/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information

   Roundrobin, like dummy, just forwards whatever it receives with no
   additional obfuscation. However, it splits up incoming data into
   blocks, and transmits each block on a different downstream connection
   (looping through the list round-robin, as the name implies).  It
   formats each block like so:

      +-------------------+
      |  Circuit ID       |
      +-------------------+
      | Offset | Len |Flag|
      +-------------------+
      /                   /
      / LEN bytes of data /
      /                   /
      +-------------------+

   (each row is 64 bits) This pseudo-TCP header is needed so that the
   other end can reassemble the data in the correct sequence.  The
   circuit ID identifies a group of downstream connections that are
   carrying data for the same upstream circuit; it is assigned by
   the connecting party.

   Unlike TCP, the offset (sequence number in TCP-ese) always starts
   at zero, but we have an explicit SYN bit anyway for great
   defensiveness (and offset wraparound).

   Blocks may be 'chaff'; no such blocks are presently generated, but
   the receiver handles them.  The data segment of a chaff block is
   discarded, and for sequencing purposes, it is treated as if
   it had had length zero.  The offset of a chaff block matters
   if it carries flags such as SYN or FIN.  */

#include "util.h"
#include "protocol.h"
#include "container.h"
#include "ht.h"

#include <stdbool.h>
#include <stdint.h>
#include <event2/buffer.h>

/* Header serialization and deserialization */

typedef struct rr_header
{
  uint64_t ckt_id;
  uint32_t offset;
  uint16_t length;
  uint16_t flags;
} rr_header;

#define RR_WIRE_HDR_LEN (sizeof(struct rr_header))
#define RR_MIN_BLOCK (RR_WIRE_HDR_LEN*2)
#define RR_MAX_BLOCK INT16_MAX

#define RR_F_SYN   0x0001
#define RR_F_FIN   0x0002
#define RR_F_CHAFF 0x0004
/* further flags values are reserved */

/* circuit ID lookups are done by hash table */
typedef struct rr_circuit_entry_t
{
  HT_ENTRY(rr_circuit_entry_t) node;
  uint64_t circuit_id;
  circuit_t *circuit;
} rr_circuit_entry_t;

typedef struct rr_circuit_table
{
  HT_HEAD(rr_circuit_table_impl, rr_circuit_entry_t) head;
} rr_circuit_table;

// this is "hash6432shift" from
// http://www.concentric.net/~Ttwang/tech/inthash.htm
static inline unsigned int
rr_circuit_id_hash(const rr_circuit_entry_t *a)
{
  uint64_t key = a->circuit_id;
  key = (~key) + (key << 18);
  key = key ^ (key >> 31);
  key = key * 21;
  key = key ^ (key >> 11);
  key = key + (key << 6);
  key = key ^ (key >> 22);
  return (unsigned int)key;
}

static inline int
rr_circuit_id_eq(const rr_circuit_id_t *a, const rr_circuit_id_t *b)
{
  return a->circuit_id == b->circuit_id;
}

HT_PROTOTYPE(rr_circuit_table_impl,
             rr_circuit_entry_t,
             node,
             rr_circuit_id_hash,
             rr_circuit_id_eq)
HT_GENERATE(rr_circuit_table_impl,
            rr_circuit_entry_t,
            node,
            rr_circuit_id_hash,
            rr_circuit_id_eq,
            0.6, xzalloc, xrealloc, free)

/* Reassembly queue.  This is a doubly-linked circular list with a
   sentinel element at the head (identified by data == 0).  List
   entries are sorted by offset.  Gaps in so-far-received data
   are "in between" entries in the list.  */

typedef struct rr_reassembly_elt
{
  struct rr_reassembly_elt *prev;
  struct rr_reassembly_elt *next;
  struct evbuffer *data;
  uint32_t offset;
  uint16_t length;
  uint16_t flags;
} rr_reassembly_elt;

/* Connections and circuits */

struct roundrobin_conn_t
{
  conn_t super;
};

struct roundrobin_circuit_t
{
  circuit_t super;
  rr_reassembly_elt reassembly_queue;
  struct evbuffer *xmit_pending;
  struct evbuffer *xmit_block;
  smartlist_t *downstreams;

  uint64_t circuit_id;
  uint32_t send_offset;
  uint32_t recv_offset;
  uint16_t next_block_size;
  uint16_t next_down;
  bool received_syn : 1;
  bool received_fin : 1;
  bool sent_syn : 1;
  bool sent_fin : 1;
};

struct roundrobin_config_t
{
  config_t super;
  struct evutil_addrinfo *up_address;
  smartlist_t *down_addresses;
  rr_circuit_table circuits;
};

/* Header serialization and deserialization */

static int
rr_send_header(struct evbuffer *buf, const struct rr_header *hdr)
{
  /* bits on the wire are in network byte order */
  uint8_t wire_header[RR_WIRE_HDR_LEN];

  wire_header[ 0] = (hdr->ckt_id & 0xFF00000000000000ull) >> 56;
  wire_header[ 1] = (hdr->ckt_id & 0x00FF000000000000ull) >> 48;
  wire_header[ 2] = (hdr->ckt_id & 0x0000FF0000000000ull) >> 40;
  wire_header[ 3] = (hdr->ckt_id & 0x000000FF00000000ull) >> 32;
  wire_header[ 4] = (hdr->ckt_id & 0x00000000FF000000ull) >> 24;
  wire_header[ 5] = (hdr->ckt_id & 0x0000000000FF0000ull) >> 16;
  wire_header[ 6] = (hdr->ckt_id & 0x000000000000FF00ull) >>  8;
  wire_header[ 7] = (hdr->ckt_id & 0x00000000000000FFull) >>  0;

  wire_header[ 8] = (hdr->offset & 0xFF000000u) >> 24;
  wire_header[ 9] = (hdr->offset & 0x00FF0000u) >> 16;
  wire_header[10] = (hdr->offset & 0x0000FF00u) >>  8;
  wire_header[11] = (hdr->offset & 0x000000FFu) >>  0;

  wire_header[12] = (hdr->length & 0xFF00u) >> 8;
  wire_header[13] = (hdr->length & 0x00FFu) >> 0;
  wire_header[14] = (hdr->flags  & 0xFF00u) >> 8;
  wire_header[15] = (hdr->flags  & 0x00FFu) >> 0;

  return evbuffer_add(buf, wire_header, RR_WIRE_HDR_LEN);
}

static int
rr_peek_header(struct evbuffer *buf, struct rr_header *hdr)
{
  uint8_t wire_header[RR_WIRE_HDR_LEN];
  if (evbuffer_get_length(buf) < RR_WIRE_HDR_LEN ||
      evbuffer_copyout(buf, wire_header, RR_WIRE_HDR_LEN) != RR_WIRE_HDR_LEN)
    return -1;

  hdr->ckt_id = ((((uint64_t)wire_header[ 0]) << 56) +
                 (((uint64_t)wire_header[ 1]) << 48) +
                 (((uint64_t)wire_header[ 2]) << 40) +
                 (((uint64_t)wire_header[ 3]) << 32) +
                 (((uint64_t)wire_header[ 4]) << 24) +
                 (((uint64_t)wire_header[ 5]) << 16) +
                 (((uint64_t)wire_header[ 6]) <<  8) +
                 (((uint64_t)wire_header[ 7]) <<  0));

  hdr->offset = ((((uint32_t)wire_header[ 8]) << 24) +
                 (((uint32_t)wire_header[ 9]) << 16) +
                 (((uint32_t)wire_header[10]) <<  8) +
                 (((uint32_t)wire_header[11]) <<  0));

  hdr->length = ((((uint16_t)wire_header[12]) << 8) +
                 (((uint16_t)wire_header[13]) << 0));

  hdr->flags  = ((((uint16_t)wire_header[14]) <<  8) +
                 (((uint16_t)wire_header[15]) <<  0));
  return 0;
}

/* True if s < t (mod 2**32). */
static inline bool
mod32_lt(uint32_t s, uint32_t t)
{
  uint32_t d = t - s;
  return 0 < d && d < 0x80000000u;
}

/* True if s <= t (mod 2**32). */
static inline bool
mod32_le(uint32_t s, uint32_t t)
{
  uint32_t d = t - s;
  return 0 <= d && d < 0x80000000u;
}

/** Add BLOCK to the reassembly queue at the appropriate location
    and merge adjacent blocks to the extent possible. */
static int
rr_reassemble_block(roundrobin_circuit_t *ckt, struct evbuffer *block,
                    rr_header *hdr)
{
  rr_reassembly_element *queue = &ckt->reassembly_queue;
  rr_reassembly_element *p, *q;

  if (hdr->flags & RR_F_CHAFF) {
    /* Chaff goes on the reassembly queue if it carries any flags that
       must be processed in sequence (SYN, FIN), but we throw away its
       contents.  Doing all chaff-handling here simplifies the caller
       at the expense of slightly more buffer-management overhead. */
    if (!(hdr->flags & (RR_F_SYN|RR_F_FIN))) {
      evbuffer_free(block);
      return 0;
    }

    hdr->length = 0;
    evbuffer_drain(block, evbuffer_get_length(block));
  }

  /* SYN must occur at offset zero, may not be duplicated, and if we
     already have anything on the reassembly queue, it must come
     logically after this block. */
  if ((hdr->flags & RR_F_SYN) &&
      (hdr->offset > 0 ||
       (queue->next != queue &&
        ((queue->next->flags & RR_F_SYN) ||
         !mod32_le(hdr->offset + hdr->length, queue->next->offset)))))
    return -1;

  /* FIN may not be duplicated and must occur logically after everything
     we've already received. */
  if ((hdr->flags & RR_F_FIN) && queue->prev != queue &&
      ((queue->prev->flags & RR_F_FIN) ||
       !mod32_le(queue->prev->offset + queue->prev->length, hdr->offset)))
    return -1;

  /* Non-SYN/FIN must come after any SYN block presently in the queue
     and before any FIN block presently in the queue. */
  if (!(hdr->flags & (RR_F_SYN|RR_F_FIN)) && queue->next != queue &&
      ((queue->next->flags && RR_F_SYN) &&
       !mod32_le(queue->next->offset + queue->next->length, hdr->offset)) ||
      ((queue->prev->flags && RR_F_FIN) &&
       !mod32_le(hdr->offset + hdr->length, queue->prev->offset)))
    return -1;

  for (p = queue->next; p != queue; p = p->next) {
    /* Try first to merge the new block into an existing one. */
    if (hdr->offset + hdr->length == p->offset)
      goto grow_front;

    if (hdr->offset == p->offset + p->length)
      goto grow_back;

    /* Does this block fit in between 'p->prev' and 'p'?
       Note: if 'p->prev->data' is NULL, it is the sentinel,
       and p->prev->offset is meaningless. */
    if (mod32_lt(hdr->offset + hdr->length, p->offset)) {
      if (!p->prev->data ||
          mod32_lt(p->prev->offset + p->prev->length, hdr->offset))
        break;

      /* protocol error: this block goes before 'p' but does not fit
         after 'p->prev' */
      return -1;
    }
  }

  /* This block goes before, but does not merge with, 'p'.
     Special case: if 'p' is the sentinel, we have not yet checked
     that this block goes after the last block in the list (aka p->prev). */
  if (!p->data && p->prev->data &&
      !mod32_lt(p->prev->offset + p->prev->length, hdr->offset))
    return -1;

  q = xzalloc(sizeof(rr_reassembly_elt));
  q->data = block;
  q->offset = hdr->offset;
  q->length = hdr->length;
  q->flags = hdr->flags;

  q->prev = p->prev;
  q->next = p;
  q->prev->next = q;
  q->next->prev = q;
  return 0;

 grow_back:
  if (evbuffer_add_buffer(p->data, block))
    return -1;
  evbuffer_free(block);
  p->length += hdr->length;
  p->flags |= hdr->flags;

  /* Can we now combine 'p' with its successor? */
  while (p->next->data && p->offset + p->length == p->next->offset) {
    q = p->next;
    if (evbuffer_add_buffer(p->data, q->data))
      return -1;
    p->length += q->length;
    p->flags |= q->flags;

    evbuffer_free(q->data);
    q->next->prev = q->prev;
    q->prev->next = q->next;
    free(q);
  }
  return 0;

 grow_front:
  if (evbuffer_prepend_buffer(p->data, block))
    return -1;
  evbuffer_free(block);
  p->length += hdr->length;
  p->offset -= hdr->length;
  p->flags |= hdr->flags;

  /* Can we now combine 'p' with its predecessor? */
  while (p->prev->data && p->offset == p->prev->offset + p->prev->length) {
    q = p->prev;
    if (evbuffer_prepend_buffer(p->data, q->data))
      return -1;
    p->length += q->length;
    p->offset -= q->length;
    p->flags |= q->flags;

    evbuffer_free(q->data);
    q->next->prev = q->prev;
    q->prev->next = q->next;
    free(q);
  }

  return 0;
}

/* Flush as much data toward upstream as we can. */
static int
rr_push_to_upstream(roundrobin_circuit_t *ckt)
{
  /* Only the first reassembly queue entry, if any, can possibly be
     ready to flush (because rr_reassemble_block ensures that there
     are gaps between all queue elements).  */
  rr_reassembly_element *ready = ckt->reassembly_queue.next;
  if (!ready->data || ckt->recv_offset != ready->offset)
    return 0;

  if (!ckt->received_syn) {
    if (!(ready->flags & RR_F_SYN))
      return 0;
    ckt->received_syn = true;
  }

  if (evbuffer_add_buffer(circuit_up_out(ckt), ready->data))
    return -1;

  ckt->recv_offset += ready->length;

  if (ready->flags & RR_F_FIN) {
    obfs_assert(!ckt->received_fin);
    obfs_assert(ready->next == &ckt->reassembly_queue);
    ckt->received_fin = true;
  }

  obfs_assert(ready->next == &ckt->reassembly_queue ||
              ready->next->offset != ckt->recv_offset);
  ready->next->prev = ready->prev;
  ready->prev->next = ready->next;

  evbuffer_free(ready->data);
  free(ready);
  return 0;
}

/* Circuit handling */

static int
rr_find_or_make_circuit(roundrobin_conn_t *conn, uint64_t circuit_id)
{
  roundrobin_config_t *cfg = conn->cfg;
  rr_circuit_entry_t *out, in;

  in.circuit_id = circuit_id;
  out = HT_FIND(rr_circuit_table_impl, &cfg->circuits.head, &in);
  if (out) {
    obfs_assert(out->circuit);
  } else {
    out = xzalloc(sizeof(rr_circuit_entry_t));
    out->circuit = circuit_create_from_downstream(conn->cfg, conn);
    if (!out->circuit) {
      free(out);
      return -1;
    }
    out->circuit_id = circuit_id;
    HT_INSERT(rr_circuit_table_impl, &cfg->circuits.head, out);
  }

  conn->circuit = out->circuit;
  smartlist_add(out->circuit->downstreams, conn);
  return 0;
}

/* Protocol methods */

int
roundrobin_circuit_send(roundrobin_circuit_t *ckt)
{
  rr_header hdr;
  size_t avail;

  if (evbuffer_add_buffer(ckt->xmit_pending, ckt->up_buffer))
    return -1;

  for (;;) {
    avail = evbuffer_get_length(ckt->xmit_pending);
    if (avail < ckt->next_block_size)
      return 0;

    if (evbuffer_get_length(ckt->xmit_block) > 0)
      return 0; /* cannot send yet */

    if (evbuffer_expand(ckt->xmit_block,
                        ckt->next_block_size + RR_WIRE_HDR_LEN))
      return -1; /* allocation failure */

    hdr.ckt_id = ckt->circuit_id;
    hdr.offset = ckt->send_offset;
    hdr.length = ckt->next_block_size;
    hdr.flags = ckt->sent_syn ? 0 : RR_F_SYN;
    if (rr_send_header(ckt->xmit_block, &hdr))
      return -1;

    if (evbuffer_remove_buffer(ckt->xmit_pending, ckt->xmit_block,
                               ckt->next_block_size) != ckt->next_block_size)
      return -1;

    if (conn_send(smartlist_get(ckt->downstreams, ckt->next_down),
                  ckt->xmit_block))
      return -1;

    ckt->next_down++;
    if (ckt->next_down == smartlist_len(ckt->downstreams))
      ckt->next_down = 0;

    ckt->send_offset += ckt->next_block_size;
    ckt->next_block_size = rng_range(RR_MIN_BLOCK, RR_MAX_BLOCK);
    ckt->sent_syn = true;
  }
}

static int
rr_circuit_recv(roundrobin_circuit_t *ckt, roundrobin_conn_t *conn)
{
  rr_header hdr;
  struct evbuffer *block;
  struct evbuffer *input = conn_get_inbound(conn);
  size_t avail;

  obfs_assert(conn->circuit == ckt);

  for (;;) {
    avail = evbuffer_get_length(input);
    if (avail < RR_MIN_BLOCK)
      break;

    if (rr_peek_header(input, &hdr))
      return -1;

    if (avail < RR_MIN_BLOCK + hdr.length)
      break;

    if (ckt->circuit_id != hdr->ckt_id)
      return -1;

    block = evbuffer_new();
    if (!block)
      return -1;

    if (evbuffer_drain(input, RR_WIRE_HDR_LEN))
      return -1;

    if (evbuffer_remove_buffer(input, block, hdr.length))
      return -1;

    if (rr_reassemble_block(ckt, block, &hdr))
      return -1;
  }

  if (rr_push_to_upstream(ckt))
    return -1;

  return 0;
}

int
roundrobin_conn_send(conn_t *dest, struct evbuffer *source)
{
  return evbuffer_add_buffer(conn_get_outbound(dest), source);
}

int
roundrobin_conn_recv(conn_t *source)
{
  if (!source->circuit) {
    rr_header hdr;
    struct evbuffer *input = conn_get_inbound(source);
    if (evbuffer_get_length(input) < RR_MIN_BLOCK)
      return 0;
    if (rr_peek_header(input, &hdr))
      return -1;
    if (rr_find_or_make_circuit(source, hdr->circuit_id))
      return -1;
  }

  return rr_circuit_recv(source->circuit, source);
}
