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

   Blocks may be 'chaff'; currently these are only generated to force
   a SYN or a FIN to happen, but the receiver handles them at any
   point.  The data segment of a chaff block is discarded, and for
   sequencing purposes, it is treated as if it had had length zero.
   The offset of a chaff block matters if it carries flags such as SYN
   or FIN.  */

#include "util.h"
#include "connections.h"
#include "container.h"
#include "crypt.h"
#include "ht.h"
#include "protocol.h"

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
#define RR_MIN_BLOCK (RR_WIRE_HDR_LEN * 2)
#define RR_MAX_BLOCK (RR_WIRE_HDR_LEN + 2048)

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

/* This is "hash6432shift" from
   http://www.concentric.net/~Ttwang/tech/inthash.htm . */
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
rr_circuit_id_eq(const rr_circuit_entry_t *a, const rr_circuit_entry_t *b)
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

typedef struct x_rr_conn_t
{
  conn_t super;
} x_rr_conn_t;

typedef struct x_rr_circuit_t
{
  circuit_t super;
  rr_reassembly_elt reassembly_queue;
  struct evbuffer *xmit_pending;
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
} x_rr_circuit_t;

typedef struct x_rr_config_t
{
  config_t super;
  struct evutil_addrinfo *up_address;
  smartlist_t *down_addresses;
  rr_circuit_table circuits;
} x_rr_config_t;

PROTO_DEFINE_MODULE(x_rr, NOSTEG);

/* Header serialization and deserialization */

static void
rr_write_header(uint8_t *wire_header, const struct rr_header *hdr)
{
  /* bits on the wire are in network byte order */
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
}

static int
rr_peek_header(struct evbuffer *buf, struct rr_header *hdr)
{
  uint8_t wire_header[RR_WIRE_HDR_LEN];
  if (evbuffer_get_length(buf) < RR_WIRE_HDR_LEN ||
      evbuffer_copyout(buf, wire_header, RR_WIRE_HDR_LEN) != RR_WIRE_HDR_LEN) {
    log_warn("rr_peek_header: not enough data copied out");
    return -1;
  }

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

/* Transmit subroutines. */

static int
rr_send_block(struct evbuffer *dest,
              struct evbuffer *source,
              struct evbuffer *block,
              uint64_t circuit_id,
              uint32_t offset,
              uint16_t length,
              uint16_t flags)
{
  rr_header hdr;
  struct evbuffer_iovec v;

  log_assert(evbuffer_get_length(block) == 0);
  log_assert(evbuffer_get_length(source) >= length);

  /* We take special care not to modify 'source' if any step fails. */
  if (evbuffer_reserve_space(block, length + RR_WIRE_HDR_LEN, &v, 1) != 1)
    return -1;
  if (v.iov_len < length + RR_WIRE_HDR_LEN)
    goto fail;

  v.iov_len = length + RR_WIRE_HDR_LEN;

  hdr.ckt_id = circuit_id;
  hdr.offset = offset;
  hdr.length = length;
  hdr.flags = flags;
  rr_write_header(v.iov_base, &hdr);

  if (evbuffer_copyout(source, (uint8_t *)v.iov_base + RR_WIRE_HDR_LEN,
                       length) != length)
    goto fail;

  if (evbuffer_commit_space(block, &v, 1))
    goto fail;

  if (evbuffer_add_buffer(dest, block))
    goto fail_committed;

  if (evbuffer_drain(source, length))
    /* this really should never happen, and we can't recover from it */
    log_abort("rr_send_block: evbuffer_drain failed"); /* does not return */

  return 0;

 fail:
  v.iov_len = 0;
  evbuffer_commit_space(block, &v, 1);
 fail_committed:
  evbuffer_drain(block, evbuffer_get_length(block));
  log_warn("rr_send_block: allocation or buffer copy failed");
  return -1;
}

static int
rr_send_blocks(circuit_t *c, int at_eof)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  struct evbuffer *xmit_block;
  conn_t *target;
  size_t avail;
  uint16_t flags;

  if (!(xmit_block = evbuffer_new())) {
    log_warn("rr_send_blocks: allocation failure");
    return -1;
  }

  for (;;) {
    avail = evbuffer_get_length(ckt->xmit_pending);
    flags = ckt->sent_syn ? 0 : RR_F_SYN;

    log_debug("rr_send_blocks: next block %u bytes data, %lu available",
              ckt->next_block_size, (unsigned long)avail);

    if (at_eof && avail > 0 && avail <= ckt->next_block_size) {
      ckt->next_block_size = avail;
      flags |= RR_F_FIN;
    } else if (avail < ckt->next_block_size)
      break;

    target = smartlist_get(ckt->downstreams, ckt->next_down);
    if (rr_send_block(conn_get_outbound(target),
                      ckt->xmit_pending,
                      xmit_block,
                      ckt->circuit_id,
                      ckt->send_offset,
                      ckt->next_block_size,
                      flags))
      goto fail;

    log_debug_cn(target, "sent %lu+%u byte block [flags %04hx]",
                 (unsigned long)RR_WIRE_HDR_LEN, ckt->next_block_size, flags);

    ckt->next_down++;
    if (ckt->next_down == smartlist_len(ckt->downstreams))
      ckt->next_down = 0;

    ckt->send_offset += ckt->next_block_size;
    ckt->next_block_size = random_range(RR_MIN_BLOCK, RR_MAX_BLOCK);
    ckt->sent_syn = true;
  }

  evbuffer_free(xmit_block);
  log_debug_ckt(c, "%lu bytes still waiting to be sent",
                (unsigned long)evbuffer_get_length(ckt->xmit_pending));
  return 0;

 fail:
  evbuffer_free(xmit_block);
  return -1;
}

static int
rr_send_chaff(circuit_t *c, int at_eof)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  struct evbuffer *chaff, *block;
  struct evbuffer_iovec v;
  conn_t *d;
  uint16_t flags;

  chaff = evbuffer_new();
  block = evbuffer_new();
  if (!chaff || !block)
    goto fail;

  if (evbuffer_reserve_space(chaff, ckt->next_block_size, &v, 1) != 1 ||
      v.iov_len < ckt->next_block_size)
    goto fail;

  v.iov_len = ckt->next_block_size;
  if (random_bytes(v.iov_base, v.iov_len) ||
      evbuffer_commit_space(chaff, &v, 1))
    goto fail;

  flags = RR_F_CHAFF;
  if (!ckt->sent_syn)
    flags |= RR_F_SYN;
  if (at_eof)
    flags |= RR_F_FIN;

  d = smartlist_get(ckt->downstreams, ckt->next_down);
  if (rr_send_block(conn_get_outbound(d), chaff, block,
                    ckt->circuit_id, ckt->send_offset,
                    ckt->next_block_size, flags))
    goto fail;

  log_debug_cn(d, "sent %lu+%u byte block [flags %04hx]",
               (unsigned long)RR_WIRE_HDR_LEN, ckt->next_block_size, flags);

  evbuffer_free(chaff);
  evbuffer_free(block);

  ckt->next_down++;
  if (ckt->next_down == smartlist_len(ckt->downstreams))
    ckt->next_down = 0;

  /* note: because this is a chaff block we just sent, it does NOT
     change the offset. */
  ckt->next_block_size = random_range(RR_MIN_BLOCK, RR_MAX_BLOCK);
  ckt->sent_syn = true;
  return 0;

 fail:
  log_warn("rr_send_chaff: failed to construct chaff block");
  if (chaff) evbuffer_free(chaff);
  if (block) evbuffer_free(block);
  return -1;
}

/* Receive subroutines. */

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
  return d < 0x80000000u;
}

/** Add BLOCK to the reassembly queue at the appropriate location
    and merge adjacent blocks to the extent possible. */
static int
rr_reassemble_block(circuit_t *c, struct evbuffer *block, rr_header *hdr)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  rr_reassembly_elt *queue = &ckt->reassembly_queue;
  rr_reassembly_elt *p, *q;

  if (hdr->flags & RR_F_CHAFF) {
    /* Chaff goes on the reassembly queue if it carries any flags that
       must be processed in sequence (SYN, FIN), but we throw away its
       contents.  Doing all chaff-handling here simplifies the caller
       at the expense of slightly more buffer-management overhead. */
    if (!(hdr->flags & (RR_F_SYN|RR_F_FIN))) {
      log_debug("rr_reassemble_block: discarding chaff with no flags");
      evbuffer_free(block);
      return 0;
    }

    hdr->length = 0;
    evbuffer_drain(block, evbuffer_get_length(block));
    log_debug("rr_reassemble_block: chaff with flags, treating length as 0");
  }

  /* SYN must occur at offset zero, may not be duplicated, and if we
     already have anything on the reassembly queue, it must come
     logically after this block. */
  if ((hdr->flags & RR_F_SYN) &&
      (hdr->offset > 0 ||
       (queue->next != queue &&
        ((queue->next->flags & RR_F_SYN) ||
         !mod32_le(hdr->offset + hdr->length, queue->next->offset))))) {
    log_warn("rr: protocol error: inappropriate SYN block");
    return -1;
  }

  /* FIN may not be duplicated and must occur logically after everything
     we've already received. */
  if ((hdr->flags & RR_F_FIN) && queue->prev != queue &&
      ((queue->prev->flags & RR_F_FIN) ||
       !mod32_le(queue->prev->offset + queue->prev->length, hdr->offset))) {
    log_warn("rr: protocol error: inappropriate FIN block");
    return -1;
  }

  /* Non-SYN/FIN must come after any SYN block presently in the queue
     and before any FIN block presently in the queue. */
  if (!(hdr->flags & (RR_F_SYN|RR_F_FIN)) && queue->next != queue &&
      (((queue->next->flags & RR_F_SYN) &&
       !mod32_le(queue->next->offset + queue->next->length, hdr->offset)) ||
       ((queue->prev->flags & RR_F_FIN) &&
        !mod32_le(hdr->offset + hdr->length, queue->prev->offset)))) {
    log_warn("rr: protocol error: inappropriate normal block");
    return -1;
  }

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
      log_warn("rr: protocol error: %u byte block does not fit at offset %u",
               hdr->length, hdr->offset);
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
  if (evbuffer_add_buffer(p->data, block)) {
    log_warn("rr_reassemble_block: failed to append to existing buffer");
    return -1;
  }
  evbuffer_free(block);
  p->length += hdr->length;
  p->flags |= hdr->flags;

  /* Can we now combine 'p' with its successor? */
  while (p->next->data && p->offset + p->length == p->next->offset) {
    q = p->next;
    if (evbuffer_add_buffer(p->data, q->data)) {
      log_warn("rr_reassemble_block: failed to merge buffers");
      return -1;
    }
    p->length += q->length;
    p->flags |= q->flags;

    evbuffer_free(q->data);
    q->next->prev = q->prev;
    q->prev->next = q->next;
    free(q);
  }
  return 0;

 grow_front:
  if (evbuffer_prepend_buffer(p->data, block)) {
    log_warn("rr_reassemble_block: failed to prepend to existing buffer");
    return -1;
  }
  evbuffer_free(block);
  p->length += hdr->length;
  p->offset -= hdr->length;
  p->flags |= hdr->flags;

  /* Can we now combine 'p' with its predecessor? */
  while (p->prev->data && p->offset == p->prev->offset + p->prev->length) {
    q = p->prev;
    if (evbuffer_prepend_buffer(p->data, q->data)) {
      log_warn("rr_reassemble_block: failed to merge buffers");
      return -1;
    }
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
rr_push_to_upstream(circuit_t *c)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  /* Only the first reassembly queue entry, if any, can possibly be
     ready to flush (because rr_reassemble_block ensures that there
     are gaps between all queue elements).  */
  rr_reassembly_elt *ready = ckt->reassembly_queue.next;
  if (!ready->data || ckt->recv_offset != ready->offset) {
    log_debug("rr_recv: no data pushable to upstream yet");
    return 0;
  }

  if (!ckt->received_syn) {
    if (!(ready->flags & RR_F_SYN)) {
      log_debug("rr_recv: waiting for SYN");
      return 0;
    }
    ckt->received_syn = true;
  }

  if (evbuffer_add_buffer(bufferevent_get_output(c->up_buffer), ready->data)) {
    log_warn("rr_recv: failure pushing data to upstream");
    return -1;
  }

  ckt->recv_offset += ready->length;

  if (ready->flags & RR_F_FIN) {
    log_assert(!ckt->received_fin);
    log_assert(ready->next == &ckt->reassembly_queue);
    ckt->received_fin = true;
    circuit_recv_eof(c);
  }

  log_assert(ready->next == &ckt->reassembly_queue ||
              ready->next->offset != ckt->recv_offset);
  ready->next->prev = ready->prev;
  ready->prev->next = ready->next;

  evbuffer_free(ready->data);
  free(ready);
  return 0;
}

/* Circuit handling */

static int
rr_find_or_make_circuit(conn_t *conn, uint64_t circuit_id)
{
  config_t *c = conn->cfg;
  x_rr_config_t *cfg = downcast_config(c);
  rr_circuit_entry_t *out, in;

  log_assert(c->mode == LSN_SIMPLE_SERVER);
  in.circuit_id = circuit_id;
  out = HT_FIND(rr_circuit_table_impl, &cfg->circuits.head, &in);
  if (out) {
    log_assert(out->circuit);
    log_debug_cn(conn, "found circuit to %s", out->circuit->up_peer);
  } else {
    out = xzalloc(sizeof(rr_circuit_entry_t));
    out->circuit = circuit_create(c);
    if (!out->circuit) {
      free(out);
      log_warn_cn(conn, "failed to create new circuit");
      return -1;
    }
    if (circuit_open_upstream(out->circuit)) {
      log_warn_cn(conn, "failed to begin upstream connection");
      circuit_close(out->circuit);
      free(out);
      return -1;
    }
    log_debug_cn(conn, "created new circuit to %s",
                   out->circuit->up_peer);
    out->circuit_id = circuit_id;
    downcast_circuit(out->circuit)->circuit_id = circuit_id;
    HT_INSERT(rr_circuit_table_impl, &cfg->circuits.head, out);
  }

  circuit_add_downstream(out->circuit, conn);
  return 0;
}

/* Protocol methods */
/**
   Helper: Parses 'options' and fills 'cfg'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      config_t *c)
{
  const char* defport;
  x_rr_config_t *cfg = downcast_config(c);
  int listen_up;
  int i;

  if (n_options < 3)
    return -1;

  /* XXXX roundrobin currently does not support socks. */
  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    c->mode = LSN_SIMPLE_CLIENT;
    listen_up = 1;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    c->mode = LSN_SOCKS_CLIENT;
    listen_up = 1;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    c->mode = LSN_SIMPLE_SERVER;
    listen_up = 0;
  } else
    return -1;

  cfg->up_address = resolve_address_port(options[1], 1, listen_up, defport);
  if (!cfg->up_address)
    return -1;

  for (i = 2; i < n_options; i++) {
    void *addr = resolve_address_port(options[i], 1, !listen_up, NULL);
    if (!addr)
      return -1;
    smartlist_add(cfg->down_addresses, addr);
  }
  return 0;
}

static void
x_rr_config_free(config_t *c)
{
  x_rr_config_t *cfg = downcast_config(c);
  rr_circuit_entry_t **ent, **next, *this;

  if (cfg->up_address)
    evutil_freeaddrinfo(cfg->up_address);
  if (cfg->down_addresses) {
    SMARTLIST_FOREACH(cfg->down_addresses, struct evutil_addrinfo *, addr,
                      evutil_freeaddrinfo(addr));
    smartlist_free(cfg->down_addresses);
  }

  for (ent = HT_START(rr_circuit_table_impl, &cfg->circuits.head);
       ent; ent = next) {
    this = *ent;
    next = HT_NEXT_RMV(rr_circuit_table_impl, &cfg->circuits.head, ent);
    if (this->circuit)
      circuit_close(this->circuit);
    free(this);
  }
  HT_CLEAR(rr_circuit_table_impl, &cfg->circuits.head);

  free(cfg);
}

static config_t *
x_rr_config_create(int n_options, const char *const *options)
{
  x_rr_config_t *cfg = xzalloc(sizeof(x_rr_config_t));
  config_t *c = upcast_config(cfg);
  c->vtable = &p_x_rr_vtable;
  c->ignore_socks_destination = 1;
  HT_INIT(rr_circuit_table_impl, &cfg->circuits.head);
  cfg->down_addresses = smartlist_create();

  if (parse_and_set_options(n_options, options, c) == 0)
    return c;

  x_rr_config_free(c);
  log_warn("roundrobin syntax:\n"
           "\tdummy <mode> <up_address> <down_address> <down_address>...\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tup_address, down_address ~ host:port\n"
           "\t\tThe down_address list is still required in socks mode.\n"
           "Examples:\n"
           "\tobfsproxy roundrobin client 127.0.0.1:5000 "
               "192.168.1.99:11253 192.168.1.99:11254 192.168.1.99:11255\n"
           "\tobfsproxy roundrobin server 127.0.0.1:9005 "
               "192.168.1.99:11253 192.168.1.99:11254 192.168.1.99:11255");
  return NULL;
}

static struct evutil_addrinfo *
x_rr_config_get_listen_addrs(config_t *c, size_t n)
{
  x_rr_config_t *cfg = downcast_config(c);
  if (c->mode == LSN_SIMPLE_SERVER) {
    if (n < (size_t)smartlist_len(cfg->down_addresses))
      return smartlist_get(cfg->down_addresses, n);
  } else {
    if (n == 0)
      return cfg->up_address;
  }
  return NULL;
}

static struct evutil_addrinfo *
x_rr_config_get_target_addrs(config_t *c, size_t n)
{
  x_rr_config_t *cfg = downcast_config(c);
  if (c->mode == LSN_SIMPLE_SERVER) {
    if (n == 0)
      return cfg->up_address;
  } else {
    if (n < (size_t)smartlist_len(cfg->down_addresses))
      return smartlist_get(cfg->down_addresses, n);
  }
  return NULL;
}

static circuit_t *
x_rr_circuit_create(config_t *cfg)
{
  x_rr_circuit_t *ckt = xzalloc(sizeof(x_rr_circuit_t));
  circuit_t *c = upcast_circuit(ckt);
  c->cfg = cfg;
  ckt->reassembly_queue.next = &ckt->reassembly_queue;
  ckt->reassembly_queue.prev = &ckt->reassembly_queue;
  ckt->next_block_size = random_range(RR_MIN_BLOCK, RR_MAX_BLOCK);
  ckt->xmit_pending = evbuffer_new();
  ckt->downstreams = smartlist_create();
  if (cfg->mode != LSN_SIMPLE_SERVER) {
    while (!ckt->circuit_id)
      random_bytes((unsigned char *)&ckt->circuit_id, sizeof(uint64_t));
  }
  return c;
}

static void
x_rr_circuit_free(circuit_t *c)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  rr_reassembly_elt *p, *q, *queue;
  rr_circuit_entry_t in;

  evbuffer_free(ckt->xmit_pending);

  SMARTLIST_FOREACH(ckt->downstreams, conn_t *, conn, {
    conn->circuit = NULL;
    conn_close(conn);
  });
  smartlist_free(ckt->downstreams);

  queue = &ckt->reassembly_queue;
  for (q = p = queue->next; p != queue; p = q) {
    q = p->next;
    if (p->data)
      evbuffer_free(p->data);
    free(p);
  }

  if (c->cfg->mode == LSN_SIMPLE_SERVER) {
    x_rr_config_t *cfg = downcast_config(c->cfg);
    in.circuit_id = ckt->circuit_id;
    free(HT_REMOVE(rr_circuit_table_impl, &cfg->circuits.head, &in));
  }
  free(ckt);
}

static void
x_rr_circuit_add_downstream(circuit_t *c, conn_t *conn)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  smartlist_add(ckt->downstreams, conn);
  log_debug_ckt(c, "added connection <%d.%d> to %s, now %d",
                c->serial, conn->serial, conn->peername,
                smartlist_len(ckt->downstreams));

  circuit_disarm_axe_timer(c);
}

static void
x_rr_circuit_drop_downstream(circuit_t *c, conn_t *conn)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  smartlist_remove(ckt->downstreams, conn);
  log_debug_ckt(c, "dropped connection <%d.%d> to %s, now %d",
                c->serial, conn->serial, conn->peername,
                smartlist_len(ckt->downstreams));

  /* If that was the last connection on this circuit AND we've both
     received and sent a FIN, close the circuit.  Otherwise, arm a
     timer that will kill off this circuit in a little while if no
     new connections happen (we might've lost all our connections to
     protocol errors).  */
  if (smartlist_len(ckt->downstreams) == 0) {
    if (ckt->sent_fin && ckt->received_fin) {
      if (evbuffer_get_length(bufferevent_get_output(c->up_buffer)) > 0)
        /* this may already have happened, but there's no harm in
           doing it again */
        circuit_do_flush(c);
      else
        circuit_close(c);
    } else
      circuit_arm_axe_timer(c, 100);
  }
}

static conn_t *
x_rr_conn_create(config_t *c)
{
  /* we don't keep any private state in conn_t */
  conn_t *cn = xzalloc(sizeof(x_rr_conn_t));
  cn->cfg = c;
  return cn;
}

static void
x_rr_conn_free(conn_t *c)
{
  free(downcast_conn(c));
}

static int
x_rr_conn_maybe_open_upstream(conn_t *conn)
{
  /* We can't open the upstream until we have a circuit ID. */
  return 0;
}

static int
x_rr_conn_handshake(conn_t *conn)
{
  /* Roundrobin has no handshake, but like dsteg, we need to send
     _something_ from the client on at least one of the channels
     shortly after connection, because the server doesn't know which
     connections go with which circuits till it hears from us.  We use
     a 1ms timeout instead of a 10ms timeout as in dsteg, because
     unlike there, the server can't even _connect to its upstream_
     till it gets the first packet from the client. */
  if (conn->cfg->mode != LSN_SIMPLE_SERVER)
    circuit_arm_flush_timer(conn->circuit, 1);
  return 0;
}

static int
x_rr_circuit_send(circuit_t *c)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);

  if (evbuffer_get_length(ckt->xmit_pending) == 0 &&
      evbuffer_get_length(bufferevent_get_input(c->up_buffer)) == 0)
    /* must-send timer expired and we still have nothing to say; send chaff */
    return rr_send_chaff(c, 0);

  if (evbuffer_add_buffer(ckt->xmit_pending,
                          bufferevent_get_input(c->up_buffer))) {
    log_warn_ckt(c, "failed to queue data");
    return -1;
  }
  return rr_send_blocks(c, 0);
}

static int
x_rr_circuit_send_eof(circuit_t *c)
{
  x_rr_circuit_t *ckt = downcast_circuit(c);
  size_t pending;

  if (smartlist_len(ckt->downstreams) == 0) {
    log_debug_ckt(c, "no downstream connections");
    ckt->sent_fin = true;
    /* see circuit_drop_downstream */
    if (ckt->received_fin)
      circuit_close(c);
    else
      circuit_arm_axe_timer(c, 100);
    return 0;
  }

  /* consume any remaining data */
  if (evbuffer_get_length(bufferevent_get_input(c->up_buffer)) > 0) {
    if (evbuffer_add_buffer(ckt->xmit_pending,
                            bufferevent_get_input(c->up_buffer))) {
      log_warn_ckt(c, "failed to queue remaining data");
      return -1;
    }
  }

  /* force out any remaining data plus a FIN */
  pending = evbuffer_get_length(ckt->xmit_pending);
  log_debug_ckt(c, "%lu bytes to send before EOF", (unsigned long)pending);
  if (pending > 0) {
    if (rr_send_blocks(c, 1)) {
      log_warn_ckt(c, "failed to transmit data and FIN");
      return -1;
    }
  } else {
    if (rr_send_chaff(c, 1)) {
      log_warn_ckt(c, "failed to transmit FIN");
      return -1;
    }
  }

  /* flush and close all downstream connections */
  ckt->sent_fin = true;
  SMARTLIST_FOREACH(ckt->downstreams, conn_t *, conn,
                    conn_send_eof(conn));

  return 0;
}

static int
x_rr_conn_recv(conn_t *conn)
{
  rr_header hdr;
  struct evbuffer *block;
  struct evbuffer *input = conn_get_inbound(conn);
  size_t avail;
  circuit_t *c;
  x_rr_circuit_t *ckt;

  if (!conn->circuit) {
    log_debug_cn(conn, "finding circuit");
    if (evbuffer_get_length(input) < RR_MIN_BLOCK) {
      log_debug_cn(conn, "not enough data to find circuit yet");
      return 0;
    }
    if (rr_peek_header(input, &hdr))
      return -1;
    if (rr_find_or_make_circuit(conn, hdr.ckt_id))
      return -1;
    log_assert(conn->circuit);
  }

  c = conn->circuit;
  ckt = downcast_circuit(c);
  log_debug_cn(conn, "circuit to %s", c->up_peer);

  for (;;) {
    avail = evbuffer_get_length(input);
    if (avail == 0)
      break;

    log_debug("rr_recv: %lu bytes available", (unsigned long)avail);
    if (avail < RR_MIN_BLOCK) {
      log_debug("rr_recv: incomplete block");
      break;
    }

    if (rr_peek_header(input, &hdr))
      return -1;

    if (avail < RR_WIRE_HDR_LEN + hdr.length) {
      log_debug("rr_recv: incomplete block (need %lu bytes)",
                (unsigned long)(RR_WIRE_HDR_LEN + hdr.length));
      break;
    }

    if (ckt->circuit_id != hdr.ckt_id) {
      log_warn("rr: protocol error: circuit id mismatch");
      return -1;
    }

    log_debug("rr_recv: receiving block of %lu+%u bytes "
              "[offset %u flags %04hx]",
              (unsigned long)RR_WIRE_HDR_LEN, hdr.length,
              hdr.offset, hdr.flags);

    block = evbuffer_new();
    if (!block) {
      log_warn("rr_recv: allocation failure");
      return -1;
    }

    if (evbuffer_drain(input, RR_WIRE_HDR_LEN)) {
      log_warn("rr_recv: failed to drain header");
      return -1;
    }

    if (evbuffer_remove_buffer(input, block, hdr.length) != hdr.length) {
      log_warn("rr_recv: failed to transfer block to reassembly queue");
      return -1;
    }

    if (rr_reassemble_block(c, block, &hdr))
      return -1;
  }

  if (rr_push_to_upstream(c))
    return -1;

  return 0;
}

static int
x_rr_conn_recv_eof(conn_t *c)
{
  /* EOF on a _connection_ does not mean EOF on a _circuit_.
     EOF on a _circuit_ occurs when rr_push_to_upstream processes a FIN.
     And we should only drop the connection from the circuit if we're
     no longer sending in the opposite direction. */
  if (c->circuit) {
    if (evbuffer_get_length(conn_get_inbound(c)) > 0)
      if (x_rr_conn_recv(c))
        return -1;

    if (downcast_circuit(c->circuit)->sent_fin)
      circuit_drop_downstream(c->circuit, c);
  }
  return 0;
}
