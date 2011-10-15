/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information

   The chopper is the core StegoTorus protocol implementation.
   For its design, see doc/chopper.tex.  Note that it is still
   being implemented, and many things that are *intended* to change
   from the toy "roundrobin" (aka "x_rr") protocol have not yet changed.  */

#include "util.h"
#include "connections.h"
#include "container.h"
#include "crypt.h"
#include "ht.h"
#include "protocol.h"
#include "steg.h"

#include <stdbool.h>
#include <stdint.h>
#include <event2/buffer.h>

/* Header serialization and deserialization */

typedef struct chop_header
{
  uint64_t ckt_id;
  uint32_t offset;
  uint16_t length;
  uint16_t flags;
} chop_header;

#define CHOP_WIRE_HDR_LEN (sizeof(struct chop_header))
#define CHOP_MAX_BLOCK (CHOP_WIRE_HDR_LEN + 2048)

#define CHOP_F_SYN   0x0001
#define CHOP_F_FIN   0x0002
#define CHOP_F_CHAFF 0x0004
/* further flags values are reserved */

/* circuit ID lookups are done by hash table */
typedef struct chop_circuit_entry_t
{
  HT_ENTRY(chop_circuit_entry_t) node;
  uint64_t circuit_id;
  circuit_t *circuit;
} chop_circuit_entry_t;

typedef struct chop_circuit_table
{
  HT_HEAD(chop_circuit_table_impl, chop_circuit_entry_t) head;
} chop_circuit_table;

/* This is "hash6432shift" from
   http://www.concentric.net/~Ttwang/tech/inthash.htm . */
static inline unsigned int
chop_circuit_id_hash(const chop_circuit_entry_t *a)
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
chop_circuit_id_eq(const chop_circuit_entry_t *a, const chop_circuit_entry_t *b)
{
  return a->circuit_id == b->circuit_id;
}

HT_PROTOTYPE(chop_circuit_table_impl,
             chop_circuit_entry_t,
             node,
             chop_circuit_id_hash,
             chop_circuit_id_eq)
HT_GENERATE(chop_circuit_table_impl,
            chop_circuit_entry_t,
            node,
            chop_circuit_id_hash,
            chop_circuit_id_eq,
            0.6, xzalloc, xrealloc, free)

/* Reassembly queue.  This is a doubly-linked circular list with a
   sentinel element at the head (identified by data == 0).  List
   entries are sorted by offset.  Gaps in so-far-received data
   are "in between" entries in the list.  */

typedef struct chop_reassembly_elt
{
  struct chop_reassembly_elt *prev;
  struct chop_reassembly_elt *next;
  struct evbuffer *data;
  uint32_t offset;
  uint16_t length;
  uint16_t flags;
} chop_reassembly_elt;

/* Connections and circuits */

typedef struct chop_conn_t
{
  conn_t super;
  steg_t *steg;
  struct evbuffer *recv_pending;
} chop_conn_t;

typedef struct chop_circuit_t
{
  circuit_t super;
  chop_reassembly_elt reassembly_queue;
  struct evbuffer *xmit_pending;
  smartlist_t *downstreams;

  uint64_t circuit_id;
  uint32_t send_offset;
  uint32_t recv_offset;
  bool received_syn : 1;
  bool received_fin : 1;
  bool sent_syn : 1;
  bool sent_fin : 1;
} chop_circuit_t;

typedef struct chop_config_t
{
  config_t super;
  struct evutil_addrinfo *up_address;
  smartlist_t *down_addresses;
  smartlist_t *steg_targets;
  chop_circuit_table circuits;
} chop_config_t;

PROTO_DEFINE_MODULE(chop, STEG);

/* Header serialization and deserialization */

static void
chop_write_header(uint8_t *wire_header, const struct chop_header *hdr)
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
chop_peek_header(struct evbuffer *buf, struct chop_header *hdr)
{
  uint8_t wire_header[CHOP_WIRE_HDR_LEN];
  if (evbuffer_get_length(buf) < CHOP_WIRE_HDR_LEN ||
      evbuffer_copyout(buf, wire_header, CHOP_WIRE_HDR_LEN) != CHOP_WIRE_HDR_LEN) {
    log_warn("chop_peek_header: not enough data copied out");
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

static conn_t *
chop_pick_connection(chop_circuit_t *ckt, size_t desired, size_t *blocksize)
{
  size_t maxbelow = 0;
  size_t minabove = SIZE_MAX;
  conn_t *targbelow = NULL;
  conn_t *targabove = NULL;

  if (desired > CHOP_MAX_BLOCK)
    desired = CHOP_MAX_BLOCK;

  /* Find the best fit for the desired transmission from all the
     outbound connections' transmit rooms. */
  SMARTLIST_FOREACH(ckt->downstreams, conn_t *, c, {
    chop_conn_t *conn = downcast_conn(c);
    /* We can only use candidates that have a steg target already. */
    if (conn->steg) {
      /* Find the connections whose transmit rooms are closest to the
         desired transmission length from both directions. */
      size_t room = steg_transmit_room(conn->steg, c);
      log_debug("chop_pick_connection: %s (%s) offers %lu bytes",
                c->peername, conn->steg->vtable->name, (unsigned long)room);
      if (room > CHOP_MAX_BLOCK)
        room = CHOP_MAX_BLOCK;

      if (room >= desired) {
        if (room < minabove) {
          minabove = room;
          targabove = c;
        }
      } else {
        if (room > maxbelow) {
          maxbelow = room;
          targbelow = c;
        }
      }
    } else {
      log_debug("chop_pick_connection: %s (no steg) offers 0 bytes",
                c->peername);
    }
  });

  /* If we have a connection that can take all the data, use it.
     Otherwise, use the connection that can take as much of the data
     as possible.  As a special case, if no connection can take data,
     targbelow, targabove, maxbelow, and minabove will all still have
     their initial values, so we'll return NULL and set blocksize to 0,
     which callers know how to handle. */
  if (targabove) {
    *blocksize = minabove;
    return targabove;
  } else {
    *blocksize = maxbelow;
    return targbelow;
  }
}

static int
chop_send_block(conn_t *d,
                chop_circuit_t *ckt,
                struct evbuffer *source,
                struct evbuffer *block,
                uint16_t length,
                uint16_t flags)
{
  chop_conn_t *dest = downcast_conn(d);
  chop_header hdr;
  struct evbuffer_iovec v;

  obfs_assert(evbuffer_get_length(block) == 0);
  obfs_assert(evbuffer_get_length(source) >= length);
  obfs_assert(dest->steg);

  /* We take special care not to modify 'source' if any step fails. */
  if (evbuffer_reserve_space(block, length + CHOP_WIRE_HDR_LEN, &v, 1) != 1)
    return -1;
  if (v.iov_len < length + CHOP_WIRE_HDR_LEN)
    goto fail;

  v.iov_len = length + CHOP_WIRE_HDR_LEN;

  hdr.ckt_id = ckt->circuit_id;
  hdr.offset = ckt->send_offset;
  hdr.length = length;
  hdr.flags = flags;
  chop_write_header(v.iov_base, &hdr);

  if (evbuffer_copyout(source, (uint8_t *)v.iov_base + CHOP_WIRE_HDR_LEN,
                       length) != length)
    goto fail;

  if (evbuffer_commit_space(block, &v, 1))
    goto fail;

  if (steg_transmit(dest->steg, block, d))
    goto fail_committed;

  if (evbuffer_drain(source, length))
    /* this really should never happen, and we can't recover from it */
    log_error("chop_send_block: evbuffer_drain failed"); /* does not return */

  if (!(flags & CHOP_F_CHAFF))
    ckt->send_offset += length;
  if (flags & CHOP_F_SYN)
    ckt->sent_syn = true;
  if (flags & CHOP_F_FIN)
    ckt->sent_fin = true;
  log_debug("chop_send_block: sent %lu+%u byte block [flags %04hx] to %s",
            CHOP_WIRE_HDR_LEN, length, flags, d->peername);
  return 0;

 fail:
  v.iov_len = 0;
  evbuffer_commit_space(block, &v, 1);
 fail_committed:
  evbuffer_drain(block, evbuffer_get_length(block));
  log_warn("chop_send_block: allocation or buffer copy failed");
  return -1;
}

static int
chop_send_blocks(circuit_t *c, int at_eof)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  struct evbuffer *xmit_block;
  conn_t *target;
  size_t avail;
  size_t blocksize;
  uint16_t flags;

  if (!(xmit_block = evbuffer_new())) {
    log_warn("chop_send_blocks: allocation failure");
    return -1;
  }

  for (;;) {
    avail = evbuffer_get_length(ckt->xmit_pending);
    flags = ckt->sent_syn ? 0 : CHOP_F_SYN;

    log_debug("chop_send_blocks: %lu bytes to send", (unsigned long)avail);

    if (avail == 0)
      break;

    target = chop_pick_connection(ckt, avail, &blocksize);
    if (!target) {
      log_debug("chop_send_blocks: no target connection available");
      /* this is not an error; it can happen e.g. when the server has
         something to send immediately and the client hasn't spoken yet */
      break;
    }

    if (avail <= blocksize) {
      blocksize = avail;
      if (at_eof)
        flags |= CHOP_F_FIN;
    }

    if (chop_send_block(target, ckt, ckt->xmit_pending, xmit_block,
                        blocksize, flags)) {
      evbuffer_free(xmit_block);
      return -1;
    }
  }

  evbuffer_free(xmit_block);
  avail = evbuffer_get_length(ckt->xmit_pending);
  if (avail)
    log_debug("%s: %lu bytes still waiting to be sent",
              c->up_peer, (unsigned long)avail);
  return 0;
}

static int
chop_send_chaff(circuit_t *c, int at_eof)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  struct evbuffer *chaff, *block;
  struct evbuffer_iovec v;
  conn_t *target;
  uint16_t flags;
  size_t blocksize;

  target = chop_pick_connection(ckt, 1, &blocksize);
  if (!target) {
    /* we only send pure chaff when we _must_ send, so this is a
       fatal condition */
    log_warn("chop_send_chaff: no target connection available");
    return -1;
  }

  blocksize = random_range(1, blocksize);

  chaff = evbuffer_new();
  block = evbuffer_new();
  if (!chaff || !block)
    goto fail;

  if (evbuffer_reserve_space(chaff, blocksize, &v, 1) != 1 ||
      v.iov_len < blocksize)
    goto fail;

  v.iov_len = blocksize;
  if (random_bytes(v.iov_base, v.iov_len) ||
      evbuffer_commit_space(chaff, &v, 1))
    goto fail;

  flags = CHOP_F_CHAFF;
  if (!ckt->sent_syn)
    flags |= CHOP_F_SYN;
  if (at_eof)
    flags |= CHOP_F_FIN;

  if (chop_send_block(target, ckt, chaff, block, blocksize, flags))
    goto fail;

  evbuffer_free(chaff);
  evbuffer_free(block);
  return 0;

 fail:
  log_warn("chop_send_chaff: failed to construct chaff block");
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
chop_reassemble_block(circuit_t *c, struct evbuffer *block, chop_header *hdr)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  chop_reassembly_elt *queue = &ckt->reassembly_queue;
  chop_reassembly_elt *p, *q;

  if (hdr->flags & CHOP_F_CHAFF) {
    /* Chaff goes on the reassembly queue if it carries any flags that
       must be processed in sequence (SYN, FIN), but we throw away its
       contents.  Doing all chaff-handling here simplifies the caller
       at the expense of slightly more buffer-management overhead. */
    if (!(hdr->flags & (CHOP_F_SYN|CHOP_F_FIN))) {
      log_debug("chop_reassemble_block: discarding chaff with no flags");
      evbuffer_free(block);
      return 0;
    }

    hdr->length = 0;
    evbuffer_drain(block, evbuffer_get_length(block));
    log_debug("chop_reassemble_block: chaff with flags, treating length as 0");
  }

  /* SYN must occur at offset zero, may not be duplicated, and if we
     already have anything on the reassembly queue, it must come
     logically after this block. */
  if ((hdr->flags & CHOP_F_SYN) &&
      (hdr->offset > 0 ||
       (queue->next != queue &&
        ((queue->next->flags & CHOP_F_SYN) ||
         !mod32_le(hdr->offset + hdr->length, queue->next->offset))))) {
    log_warn("chop: protocol error: inappropriate SYN block");
    return -1;
  }

  /* FIN may not be duplicated and must occur logically after everything
     we've already received. */
  if ((hdr->flags & CHOP_F_FIN) && queue->prev != queue &&
      ((queue->prev->flags & CHOP_F_FIN) ||
       !mod32_le(queue->prev->offset + queue->prev->length, hdr->offset))) {
    log_warn("chop: protocol error: inappropriate FIN block");
    return -1;
  }

  /* Non-SYN/FIN must come after any SYN block presently in the queue
     and before any FIN block presently in the queue. */
  if (!(hdr->flags & (CHOP_F_SYN|CHOP_F_FIN)) && queue->next != queue &&
      (((queue->next->flags & CHOP_F_SYN) &&
        !mod32_le(queue->next->offset + queue->next->length, hdr->offset)) ||
       ((queue->prev->flags & CHOP_F_FIN) &&
        !mod32_le(hdr->offset + hdr->length, queue->prev->offset)))) {
    log_warn("chop: protocol error: inappropriate normal block");
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
      log_warn("chop: protocol error: %u byte block does not fit at offset %u",
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

  q = xzalloc(sizeof(chop_reassembly_elt));
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
    log_warn("chop_reassemble_block: failed to append to existing buffer");
    return -1;
  }
  evbuffer_free(block);
  p->length += hdr->length;
  p->flags |= hdr->flags;

  /* Can we now combine 'p' with its successor? */
  while (p->next->data && p->offset + p->length == p->next->offset) {
    q = p->next;
    if (evbuffer_add_buffer(p->data, q->data)) {
      log_warn("chop_reassemble_block: failed to merge buffers");
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
    log_warn("chop_reassemble_block: failed to prepend to existing buffer");
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
      log_warn("chop_reassemble_block: failed to merge buffers");
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
chop_push_to_upstream(circuit_t *c)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  /* Only the first reassembly queue entry, if any, can possibly be
     ready to flush (because chop_reassemble_block ensures that there
     are gaps between all queue elements).  */
  chop_reassembly_elt *ready = ckt->reassembly_queue.next;
  if (!ready->data || ckt->recv_offset != ready->offset) {
    log_debug("chop_recv: no data pushable to upstream yet");
    return 0;
  }

  if (!ckt->received_syn) {
    if (!(ready->flags & CHOP_F_SYN)) {
      log_debug("chop_recv: waiting for SYN");
      return 0;
    }
    ckt->received_syn = true;
  }

  if (evbuffer_add_buffer(bufferevent_get_output(c->up_buffer), ready->data)) {
    log_warn("chop_recv: failure pushing data to upstream");
    return -1;
  }

  ckt->recv_offset += ready->length;

  if (ready->flags & CHOP_F_FIN) {
    obfs_assert(!ckt->received_fin);
    obfs_assert(ready->next == &ckt->reassembly_queue);
    ckt->received_fin = true;
    circuit_recv_eof(c);
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
chop_find_or_make_circuit(conn_t *conn, uint64_t circuit_id)
{
  config_t *c = conn->cfg;
  chop_config_t *cfg = downcast_config(c);
  chop_circuit_entry_t *out, in;

  obfs_assert(c->mode == LSN_SIMPLE_SERVER);
  in.circuit_id = circuit_id;
  out = HT_FIND(chop_circuit_table_impl, &cfg->circuits.head, &in);
  if (out) {
    obfs_assert(out->circuit);
    log_debug("chop_recv: found circuit to %s for connection from %s",
              out->circuit->up_peer, conn->peername);
  } else {
    out = xzalloc(sizeof(chop_circuit_entry_t));
    out->circuit = circuit_create(c);
    if (!out->circuit) {
      free(out);
      log_warn("chop_recv: failed to create new circuit for %s",
               conn->peername);
      return -1;
    }
    if (circuit_open_upstream(out->circuit)) {
      log_warn("chop_recv: failed to begin upstream connection for %s",
               conn->peername);
      circuit_close(out->circuit);
      free(out);
      return -1;
    }
    log_debug("chop_recv: new circuit to %s for connection from %s",
              out->circuit->up_peer, conn->peername);
    out->circuit_id = circuit_id;
    downcast_circuit(out->circuit)->circuit_id = circuit_id;
    HT_INSERT(chop_circuit_table_impl, &cfg->circuits.head, out);
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
  chop_config_t *cfg = downcast_config(c);
  int listen_up;
  int i;

  if (n_options < 4)
    return -1;

  /* XXXX chopper currently does not support socks. */
  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    c->mode = LSN_SIMPLE_CLIENT;
    cfg->steg_targets = smartlist_create();
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

  /* From here on out, arguments alternate between downstream
     addresses and steg targets, if we're the client.  If we're not
     the client, the arguments are just downstream addresses. */
  for (i = 2; i < n_options; i++) {
    void *addr = resolve_address_port(options[i], 1, !listen_up, NULL);
    if (!addr)
      return -1;
    smartlist_add(cfg->down_addresses, addr);

    if (c->mode == LSN_SIMPLE_SERVER)
      continue;
    i++;
    if (i == n_options) return -1;

    if (!steg_is_supported(options[i]))
      return -1;
    smartlist_add(cfg->steg_targets, (void *)options[i]);
  }
  return 0;
}

static void
chop_config_free(config_t *c)
{
  chop_config_t *cfg = downcast_config(c);
  chop_circuit_entry_t **ent, **next, *this;

  if (cfg->up_address)
    evutil_freeaddrinfo(cfg->up_address);
  if (cfg->down_addresses) {
    SMARTLIST_FOREACH(cfg->down_addresses, struct evutil_addrinfo *, addr,
                      evutil_freeaddrinfo(addr));
    smartlist_free(cfg->down_addresses);
  }

  /* The strings in cfg->steg_targets are not on the heap. */
  if (cfg->steg_targets)
    smartlist_free(cfg->steg_targets);

  for (ent = HT_START(chop_circuit_table_impl, &cfg->circuits.head);
       ent; ent = next) {
    this = *ent;
    next = HT_NEXT_RMV(chop_circuit_table_impl, &cfg->circuits.head, ent);
    if (this->circuit)
      circuit_close(this->circuit);
    free(this);
  }
  HT_CLEAR(chop_circuit_table_impl, &cfg->circuits.head);

  free(cfg);
}

static config_t *
chop_config_create(int n_options, const char *const *options)
{
  chop_config_t *cfg = xzalloc(sizeof(chop_config_t));
  config_t *c = upcast_config(cfg);
  c->vtable = &p_chop_vtable;
  HT_INIT(chop_circuit_table_impl, &cfg->circuits.head);
  cfg->down_addresses = smartlist_create();

  if (parse_and_set_options(n_options, options, c) == 0)
    return c;

  chop_config_free(c);
  log_warn("chop syntax:\n"
           "\tchop <mode> <up_address> (<down_address> [<steg>])...\n"
           "\t\tmode ~ server|client\n"
           "\t\tup_address, down_address ~ host:port\n"
           "\t\ta steg target is required for each down_address,\n"
           "\t\tin client mode only, and forbidden otherwise."
           "Examples:\n"
           "\tobfsproxy chop client 127.0.0.1:5000 "
           "192.168.1.99:11253 http 192.168.1.99:11254 skype\n"
           "\tobfsproxy roundrobin server 127.0.0.1:9005 "
           "192.168.1.99:11253 192.168.1.99:11254");
  return NULL;
}

static struct evutil_addrinfo *
chop_config_get_listen_addrs(config_t *c, size_t n)
{
  chop_config_t *cfg = downcast_config(c);
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
chop_config_get_target_addrs(config_t *c, size_t n)
{
  chop_config_t *cfg = downcast_config(c);
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
chop_circuit_create(config_t *cfg)
{
  chop_circuit_t *ckt = xzalloc(sizeof(chop_circuit_t));
  circuit_t *c = upcast_circuit(ckt);
  c->cfg = cfg;
  ckt->reassembly_queue.next = &ckt->reassembly_queue;
  ckt->reassembly_queue.prev = &ckt->reassembly_queue;
  ckt->xmit_pending = evbuffer_new();
  ckt->downstreams = smartlist_create();
  if (cfg->mode != LSN_SIMPLE_SERVER) {
    while (!ckt->circuit_id)
      random_bytes((unsigned char *)&ckt->circuit_id, sizeof(uint64_t));
  }
  return c;
}

static void
chop_circuit_free(circuit_t *c)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  chop_reassembly_elt *p, *q, *queue;
  chop_circuit_entry_t in;

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
    chop_config_t *cfg = downcast_config(c->cfg);
    in.circuit_id = ckt->circuit_id;
    free(HT_REMOVE(chop_circuit_table_impl, &cfg->circuits.head, &in));
  }
  free(ckt);
}

static void
chop_circuit_add_downstream(circuit_t *c, conn_t *conn)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  smartlist_add(ckt->downstreams, conn);
  log_debug("%s: added connection to %s, now %d",
            c->up_peer, conn->peername, smartlist_len(ckt->downstreams));

  circuit_disarm_axe_timer(c);
}

static void
chop_circuit_drop_downstream(circuit_t *c, conn_t *conn)
{
  chop_circuit_t *ckt = downcast_circuit(c);
  smartlist_remove(ckt->downstreams, conn);
  log_debug("%s: removed connection to %s, now %d",
            c->up_peer, conn->peername, smartlist_len(ckt->downstreams));

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
chop_conn_create(config_t *c)
{
  chop_config_t *cfg = downcast_config(c);
  chop_conn_t *conn = xzalloc(sizeof(chop_conn_t));
  conn_t *cn = upcast_conn(conn);
  cn->cfg = c;
  if (c->mode != LSN_SIMPLE_SERVER) {
    /* XXX currently uses steg target 0 for all connections.
       Need protocol-specific listener state to fix this. */
    conn->steg = steg_new(smartlist_get(cfg->steg_targets, 0));
    if (!conn->steg) {
      free(conn);
      return 0;
    }
  }
  conn->recv_pending = evbuffer_new();
  return cn;
}

static void
chop_conn_free(conn_t *c)
{
  chop_conn_t *conn = downcast_conn(c);
  if (conn->steg)
    steg_del(conn->steg);
  evbuffer_free(conn->recv_pending);
  free(conn);
}

static int
chop_conn_maybe_open_upstream(conn_t *conn)
{
  /* We can't open the upstream until we have a circuit ID. */
  return 0;
}

static int
chop_conn_handshake(conn_t *conn)
{
  /* Chop has no handshake as such, but like dsteg, we need to send
     _something_ from the client on at least one of the channels
     shortly after connection, because the server doesn't know which
     connections go with which circuits till it hears from us, _and_
     it doesn't know what steganography to use.  We use a 1ms timeout
     instead of a 10ms timeout as in dsteg, because unlike there, the
     server can't even _connect to its upstream_ till it gets the
     first packet from the client. */
  if (conn->cfg->mode != LSN_SIMPLE_SERVER)
    circuit_arm_flush_timer(conn->circuit, 1);
  return 0;
}

static int
chop_circuit_send(circuit_t *c)
{
  chop_circuit_t *ckt = downcast_circuit(c);

  circuit_disarm_flush_timer(c);

  if (evbuffer_get_length(ckt->xmit_pending) == 0 &&
      evbuffer_get_length(bufferevent_get_input(c->up_buffer)) == 0)
    /* must-send timer expired and we still have nothing to say; send chaff */
    return chop_send_chaff(c, 0);

  if (evbuffer_add_buffer(ckt->xmit_pending,
                          bufferevent_get_input(c->up_buffer))) {
    log_warn("%s: chop_send: failed to queue data", c->up_peer);
    return -1;
  }
  return chop_send_blocks(c, 0);
}

static int
chop_circuit_send_eof(circuit_t *c)
{
  chop_circuit_t *ckt = downcast_circuit(c);

  if (smartlist_len(ckt->downstreams) == 0) {
    log_debug("%s: chop_send_eof: no downstreams", c->up_peer);
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
      log_warn("%s: chop_send_eof: failed to queue remaining data", c->up_peer);
      return -1;
    }
  }

  /* force out any remaining data plus a FIN */
  if (evbuffer_get_length(ckt->xmit_pending) > 0) {
    log_debug("%s: %lu bytes to send before EOF", c->up_peer,
              (unsigned long)evbuffer_get_length(ckt->xmit_pending));
    if (chop_send_blocks(c, 1)) {
      log_warn("%s: chop_send_eof: failed to transmit data and FIN",
               c->up_peer);
      return -1;
    }
  } else {
    log_debug("%s: 0 bytes to send before EOF", c->up_peer);
    if (chop_send_chaff(c, 1)) {
      log_warn("%s: chop_send_eof: failed to transmit FIN", c->up_peer);
      return -1;
    }
  }

  SMARTLIST_FOREACH(ckt->downstreams, conn_t *, conn,
                    conn_send_eof(conn));
  return 0;
}

static int
chop_conn_recv(conn_t *s)
{
  chop_conn_t *source = downcast_conn(s);
  circuit_t *c;
  chop_circuit_t *ckt;
  chop_header hdr;
  struct evbuffer *block;
  size_t avail;

  if (!source->steg) {
    obfs_assert(s->cfg->mode == LSN_SIMPLE_SERVER);
    if (evbuffer_get_length(conn_get_inbound(s)) == 0)
      return 0; /* need more data */
    source->steg = steg_detect(s);
    if (!source->steg) {
      log_debug("%s: no recognized steg pattern detected", s->peername);
      return -1;
    } else {
      log_debug("%s: detected steg pattern %s",
                s->peername, source->steg->vtable->name);
    }
  }

  if (steg_receive(source->steg, s, source->recv_pending))
    return -1;

  if (!s->circuit) {
    log_debug("chop_recv: finding circuit for connection with %s",
              s->peername);
    if (evbuffer_get_length(source->recv_pending) < CHOP_WIRE_HDR_LEN) {
      log_debug("chop_recv: not enough data to find circuit yet");
      return 0;
    }
    if (chop_peek_header(source->recv_pending, &hdr))
      return -1;
    if (chop_find_or_make_circuit(s, hdr.ckt_id))
      return -1;
    obfs_assert(s->circuit);
  }

  c = s->circuit;
  ckt = downcast_circuit(c);
  log_debug("chop_recv: connection to %s, circuit to %s",
            s->peername, c->up_peer);

  for (;;) {
    avail = evbuffer_get_length(source->recv_pending);
    if (avail == 0)
      break;

    log_debug("chop_recv: %ld bytes available", (unsigned long)avail);
    if (avail < CHOP_WIRE_HDR_LEN) {
      log_debug("chop_recv: incomplete block");
      break;
    }

    if (chop_peek_header(source->recv_pending, &hdr))
      return -1;

    if (avail < CHOP_WIRE_HDR_LEN + hdr.length) {
      log_debug("chop_recv: incomplete block (need %ld bytes)",
                CHOP_WIRE_HDR_LEN + hdr.length);
      break;
    }

    if (ckt->circuit_id != hdr.ckt_id) {
      log_warn("chop: protocol error: circuit id mismatch");
      return -1;
    }

    log_debug("chop_recv: receiving block of %lu+%u bytes "
              "[offset %u flags %04hx]",
              CHOP_WIRE_HDR_LEN, hdr.length, hdr.offset, hdr.flags);

    block = evbuffer_new();
    if (!block) {
      log_warn("chop_recv: allocation failure");
      return -1;
    }

    if (evbuffer_drain(source->recv_pending, CHOP_WIRE_HDR_LEN)) {
      log_warn("chop_recv: failed to drain header");
      return -1;
    }

    if (evbuffer_remove_buffer(source->recv_pending, block, hdr.length)
        != hdr.length) {
      log_warn("chop_recv: failed to transfer block to reassembly queue");
      return -1;
    }

    if (chop_reassemble_block(c, block, &hdr))
      return -1;
  }

  if (chop_push_to_upstream(c))
    return -1;

  return 0;
}

static int
chop_conn_recv_eof(conn_t *c)
{
  /* EOF on a _connection_ does not mean EOF on a _circuit_.
     EOF on a _circuit_ occurs when chop_push_to_upstream processes a FIN.
     And we should only drop the connection from the circuit if we're
     no longer sending in the opposite direction. */
  if (c->circuit) {
    if (evbuffer_get_length(conn_get_inbound(c)) > 0)
      if (chop_conn_recv(c))
        return -1;

    if (downcast_circuit(c->circuit)->sent_fin)
      circuit_drop_downstream(c->circuit, c);
  }
  return 0;
}

/** XXX all steg callbacks are ignored */
static void chop_conn_expect_close(conn_t *conn) {}
static void chop_conn_cease_transmission(conn_t *conn) {}
static void chop_conn_close_after_transmit(conn_t *conn) {}
static void chop_conn_transmit_soon(conn_t *conn, unsigned long timeout) {}
