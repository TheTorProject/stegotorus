/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information

   The chopper is the core StegoTorus protocol implementation.
   For its design, see doc/chopper.tex.  Note that it is still
   being implemented, and many things that are *intended* to change
   from the toy "roundrobin" (aka "x_rr") protocol have not yet changed.  */

#include "util.h"
#include "connections.h"
#include "crypt.h"
#include "protocol.h"
#include "rng.h"
#include "steg.h"

#include <tr1/unordered_map>
#include <tr1/unordered_set>
#include <vector>

#include <event2/event.h>
#include <event2/buffer.h>

using std::tr1::unordered_map;
using std::tr1::unordered_set;
using std::vector;

/* Header serialization and deserialization */

struct chop_header
{
  uint64_t ckt_id;
  uint8_t  pkt_iv[8];
  uint32_t offset;
  uint16_t length;
  uint16_t flags;
};

#define CHOP_WIRE_HDR_LEN (sizeof(struct chop_header))
#define CHOP_MAX_DATA 16384
#define CHOP_MAX_CHAFF 2048

#define CHOP_F_SYN   0x0001
#define CHOP_F_FIN   0x0002
#define CHOP_F_CHAFF 0x0004
/* further flags values are reserved */

/* Reassembly queue.  This is a doubly-linked circular list with a
   sentinel element at the head (identified by data == 0).  List
   entries are sorted by offset.  Gaps in so-far-received data
   are "in between" entries in the list.  */

struct chop_reassembly_elt
{
  struct chop_reassembly_elt *prev;
  struct chop_reassembly_elt *next;
  struct evbuffer *data;
  uint32_t offset;
  uint16_t length;
  uint16_t flags;
};

/* Horrifically crude "encryption".  Uses a compiled-in pair of
   encryption keys, no MAC, and recycles the circuit ID as a
   partial IV.  To be replaced with something less laughable ASAP. */

static const uint8_t c2s_key[] =
  "\x44\x69\x5f\x45\x41\x67\xe9\x69\x14\x6c\x5f\xd2\x41\x63\xc4\x02";
static const uint8_t s2c_key[] =
  "\xfa\x31\x78\x6c\xb9\x4c\x66\x2a\xd0\x30\x59\xf7\x28\x22\x2f\x22";

/* Connections and circuits */

typedef unordered_map<uint64_t, circuit_t *> chop_circuit_table;

namespace {
  struct chop_conn_t : conn_t
  {
    steg_t *steg;
    struct evbuffer *recv_pending;
    struct event *must_transmit_timer;
    bool no_more_transmissions : 1;

    CONN_DECLARE_METHODS(chop);
  };

  struct chop_circuit_t : circuit_t
  {
    chop_reassembly_elt reassembly_queue;
    unordered_set<conn_t *> downstreams;
    encryptor *send_crypt;
    decryptor *recv_crypt;

    uint64_t circuit_id;
    uint32_t send_offset;
    uint32_t recv_offset;
    bool received_syn : 1;
    bool received_fin : 1;
    bool sent_syn : 1;
    bool sent_fin : 1;
    bool upstream_eof : 1;

    CIRCUIT_DECLARE_METHODS(chop);
  };

  struct chop_config_t : config_t
  {
    struct evutil_addrinfo *up_address;
    vector<struct evutil_addrinfo *> down_addresses;
    vector<const char *> steg_targets;
    chop_circuit_table circuits;

    CONFIG_DECLARE_METHODS(chop);
  };
}

PROTO_DEFINE_MODULE(chop);

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

  wire_header[ 8] = hdr->pkt_iv[0];
  wire_header[ 9] = hdr->pkt_iv[1];
  wire_header[10] = hdr->pkt_iv[2];
  wire_header[11] = hdr->pkt_iv[3];
  wire_header[12] = hdr->pkt_iv[4];
  wire_header[13] = hdr->pkt_iv[5];
  wire_header[14] = hdr->pkt_iv[6];
  wire_header[15] = hdr->pkt_iv[7];

  wire_header[16] = (hdr->offset & 0xFF000000u) >> 24;
  wire_header[17] = (hdr->offset & 0x00FF0000u) >> 16;
  wire_header[18] = (hdr->offset & 0x0000FF00u) >>  8;
  wire_header[19] = (hdr->offset & 0x000000FFu) >>  0;

  wire_header[20] = (hdr->length & 0xFF00u) >> 8;
  wire_header[21] = (hdr->length & 0x00FFu) >> 0;
  wire_header[22] = (hdr->flags  & 0xFF00u) >> 8;
  wire_header[23] = (hdr->flags  & 0x00FFu) >> 0;
}

static int
chop_peek_circuit_id(struct evbuffer *buf, struct chop_header *hdr)
{
  uint8_t wire_id[8];
  if (evbuffer_copyout(buf, wire_id, 8) != 8)
    return -1;
  hdr->ckt_id = ((((uint64_t)wire_id[ 0]) << 56) +
                 (((uint64_t)wire_id[ 1]) << 48) +
                 (((uint64_t)wire_id[ 2]) << 40) +
                 (((uint64_t)wire_id[ 3]) << 32) +
                 (((uint64_t)wire_id[ 4]) << 24) +
                 (((uint64_t)wire_id[ 5]) << 16) +
                 (((uint64_t)wire_id[ 6]) <<  8) +
                 (((uint64_t)wire_id[ 7]) <<  0));
  return 0;
}

static int
chop_decrypt_header(chop_circuit_t *ckt,
                    struct evbuffer *buf,
                    struct chop_header *hdr)
{
  uint8_t wire_header[CHOP_WIRE_HDR_LEN];
  uint8_t decoded_header[CHOP_WIRE_HDR_LEN-16];

  if (evbuffer_copyout(buf, wire_header, CHOP_WIRE_HDR_LEN)
      != CHOP_WIRE_HDR_LEN) {
    log_warn("not enough data copied out");
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

  hdr->pkt_iv[0] = wire_header[ 8];
  hdr->pkt_iv[1] = wire_header[ 9];
  hdr->pkt_iv[2] = wire_header[10];
  hdr->pkt_iv[3] = wire_header[11];
  hdr->pkt_iv[4] = wire_header[12];
  hdr->pkt_iv[5] = wire_header[13];
  hdr->pkt_iv[6] = wire_header[14];
  hdr->pkt_iv[7] = wire_header[15];

  /* The full IV is the circuit ID plus packet ID *as it is on the
     wire*. */
  ckt->recv_crypt->decrypt_unchecked(decoded_header,
                                     wire_header + 16, CHOP_WIRE_HDR_LEN - 16,
                                     wire_header, 16);

  hdr->offset = ((((uint32_t)decoded_header[0]) << 24) +
                 (((uint32_t)decoded_header[1]) << 16) +
                 (((uint32_t)decoded_header[2]) <<  8) +
                 (((uint32_t)decoded_header[3]) <<  0));

  hdr->length = ((((uint16_t)decoded_header[4]) << 8) +
                 (((uint16_t)decoded_header[5]) << 0));

  hdr->flags  = ((((uint16_t)decoded_header[6]) <<  8) +
                 (((uint16_t)decoded_header[7]) <<  0));

  log_debug("decoded offset %u length %hu flags %04hx",
            hdr->offset, hdr->length, hdr->flags);
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

  if (desired > CHOP_MAX_DATA)
    desired = CHOP_MAX_DATA;

  /* Find the best fit for the desired transmission from all the
     outbound connections' transmit rooms. */
  for (unordered_set<conn_t *>::iterator i = ckt->downstreams.begin();
       i != ckt->downstreams.end(); i++) {
    chop_conn_t *conn = static_cast<chop_conn_t *>(*i);
    /* We can only use candidates that have a steg target already. */
    if (conn->steg) {
      /* Find the connections whose transmit rooms are closest to the
         desired transmission length from both directions. */
      size_t room = conn->steg->transmit_room(conn);
      log_debug(conn, "offers %lu bytes (%s)", (unsigned long)room,
                conn->steg->name());

      if (room > CHOP_MAX_DATA)
        room = CHOP_MAX_DATA;

      if (room >= desired) {
        if (room < minabove) {
          minabove = room;
          targabove = conn;
        }
      } else {
        if (room > maxbelow) {
          maxbelow = room;
          targbelow = conn;
        }
      }
    } else {
      log_debug(conn, "offers 0 bytes (no steg)");
    }
  }

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
  chop_conn_t *dest = static_cast<chop_conn_t *>(d);
  chop_header hdr;
  struct evbuffer_iovec v;
  uint8_t *p;

  log_assert(evbuffer_get_length(block) == 0);
  log_assert(evbuffer_get_length(source) >= length);
  log_assert(dest->steg);

  /* We take special care not to modify 'source' if any step fails. */
  if (evbuffer_reserve_space(block,
                             length + CHOP_WIRE_HDR_LEN + GCM_TAG_LEN,
                             &v, 1) != 1)
    return -1;
  if (v.iov_len < length + CHOP_WIRE_HDR_LEN + GCM_TAG_LEN)
    goto fail;

  v.iov_len = length + CHOP_WIRE_HDR_LEN + GCM_TAG_LEN;

  hdr.ckt_id = ckt->circuit_id;
  hdr.offset = ckt->send_offset;
  hdr.length = length;
  hdr.flags = flags;
  rng_bytes(hdr.pkt_iv, 8);
  chop_write_header((uint8_t*)v.iov_base, &hdr);

  if (evbuffer_copyout(source, (uint8_t *)v.iov_base + CHOP_WIRE_HDR_LEN,
                       length) != length)
    goto fail;

  p = (uint8_t *)v.iov_base;
  ckt->send_crypt->encrypt(p + 16, p + 16, length + CHOP_WIRE_HDR_LEN - 16,
                           p, 16);

  if (evbuffer_commit_space(block, &v, 1))
    goto fail;

  if (dest->steg->transmit(block, dest))
    goto fail_committed;

  if (evbuffer_drain(source, length))
    /* this really should never happen, and we can't recover from it */
    log_abort(dest, "evbuffer_drain failed"); /* does not return */

  if (!(flags & CHOP_F_CHAFF))
    ckt->send_offset += length;
  if (flags & CHOP_F_SYN)
    ckt->sent_syn = true;
  if (flags & CHOP_F_FIN)
    ckt->sent_fin = true;
  log_debug(dest, "sent %lu+%u byte block [flags %04hx]",
            (unsigned long)CHOP_WIRE_HDR_LEN, length, flags);
  if (dest->must_transmit_timer)
    evtimer_del(dest->must_transmit_timer);
  return 0;

 fail:
  v.iov_len = 0;
  evbuffer_commit_space(block, &v, 1);
 fail_committed:
  evbuffer_drain(block, evbuffer_get_length(block));
  log_warn(dest, "allocation or buffer copy failed");
  return -1;
}

static int
chop_send_blocks(circuit_t *c)
{
  chop_circuit_t *ckt = static_cast<chop_circuit_t *>(c);
  struct evbuffer *xmit_pending = bufferevent_get_input(c->up_buffer);
  struct evbuffer *block;
  conn_t *target;
  size_t avail;
  size_t blocksize;
  uint16_t flags;

  if (!(block = evbuffer_new())) {
    log_warn(c, "allocation failure");
    return -1;
  }

  for (;;) {
    avail = evbuffer_get_length(xmit_pending);
    flags = ckt->sent_syn ? 0 : CHOP_F_SYN;

    log_debug(c, "%lu bytes to send", (unsigned long)avail);

    if (avail == 0)
      break;

    target = chop_pick_connection(ckt, avail, &blocksize);
    if (!target) {
      log_debug(c, "no target connection available");
      /* this is not an error; it can happen e.g. when the server has
         something to send immediately and the client hasn't spoken yet */
      break;
    }

    if (avail <= blocksize) {
      blocksize = avail;
      if (ckt->upstream_eof && !ckt->sent_fin)
        flags |= CHOP_F_FIN;
    }

    if (chop_send_block(target, ckt, xmit_pending, block, blocksize, flags)) {
      evbuffer_free(block);
      return -1;
    }
  }

  evbuffer_free(block);
  avail = evbuffer_get_length(xmit_pending);
  if (avail)
    log_debug(c, "%lu bytes still waiting to be sent", (unsigned long)avail);
  return 0;
}

static int
chop_send_targeted(circuit_t *c, conn_t *target, size_t blocksize)
{
  chop_circuit_t *ckt = static_cast<chop_circuit_t *>(c);
  struct evbuffer *xmit_pending = bufferevent_get_input(c->up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  struct evbuffer *block = evbuffer_new();
  uint16_t flags = 0;

  log_debug(target, "%lu bytes available, %lu bytes room",
            (unsigned long)avail, (unsigned long)blocksize);
  if (!block) {
    log_warn(target, "allocation failure");
    return -1;
  }

  if (!ckt->sent_syn)
    flags |= CHOP_F_SYN;

  if (avail) {
    if (avail <= blocksize) {
      blocksize = avail;
      if (ckt->upstream_eof && !ckt->sent_fin)
        flags |= CHOP_F_FIN;
    }


    if (chop_send_block(target, ckt, xmit_pending, block, blocksize, flags)) {
      evbuffer_free(block);
      return -1;
    }

    evbuffer_free(block);
    avail = evbuffer_get_length(xmit_pending);
    if (avail)
      log_debug(c, "%lu bytes still waiting to be sent", (unsigned long)avail);
    return 0;

  } else {
    struct evbuffer *chaff;
    struct evbuffer_iovec v;

    if (blocksize > CHOP_MAX_CHAFF)
      blocksize = CHOP_MAX_CHAFF;

    blocksize = rng_range(1, blocksize);
    log_debug(target, "generating %lu bytes chaff", (unsigned long)blocksize);

    chaff = evbuffer_new();
    if (!chaff ||
        evbuffer_reserve_space(chaff, blocksize, &v, 1) != 1 ||
        v.iov_len < blocksize)
      goto fail;

    v.iov_len = blocksize;
    memset(v.iov_base, 0, v.iov_len);
    if (evbuffer_commit_space(chaff, &v, 1))
      goto fail;

    flags |= CHOP_F_CHAFF;
    if (ckt->upstream_eof && !ckt->sent_fin)
      flags |= CHOP_F_FIN;
    if (chop_send_block(target, ckt, chaff, block, blocksize, flags))
      goto fail;

    evbuffer_free(chaff);
    evbuffer_free(block);
    return 0;

  fail:
    log_warn(target, "failed to construct chaff block");
    if (chaff) evbuffer_free(chaff);
    if (block) evbuffer_free(block);
    return -1;
  }
}

static int
chop_send_chaff(circuit_t *c)
{
  chop_circuit_t *ckt = static_cast<chop_circuit_t *>(c);
  size_t room;

  conn_t *target = chop_pick_connection(ckt, 1, &room);
  if (!target) {
    /* If we have connections and we can't send, that means we're waiting
       for the server to respond.  Just wait. */
    return 0;
  }
  return chop_send_targeted(c, target, room);
}

static void
must_transmit_timer_cb(evutil_socket_t, short, void *arg)
{
  chop_conn_t *conn = static_cast<chop_conn_t*>(arg);
  size_t room;

  if (!conn->circuit) {
    log_debug(conn, "must transmit, but no circuit (stale connection)");
    conn_do_flush(conn);
    return;
  }

  if (!conn->steg) {
    log_warn(conn, "must transmit, but no steg module available");
    return;
  }
  room = conn->steg->transmit_room(conn);
  if (!room) {
    log_warn(conn, "must transmit, but no transmit room");
    return;
  }

  log_debug(conn, "must transmit");
  chop_send_targeted(conn->circuit, conn, room);
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
  chop_circuit_t *ckt = static_cast<chop_circuit_t *>(c);
  chop_reassembly_elt *queue = &ckt->reassembly_queue;
  chop_reassembly_elt *p, *q;

  if (hdr->flags & CHOP_F_CHAFF) {
    /* Chaff goes on the reassembly queue if it carries any flags that
       must be processed in sequence (SYN, FIN), but we throw away its
       contents.  Doing all chaff-handling here simplifies the caller
       at the expense of slightly more buffer-management overhead. */
    if (!(hdr->flags & (CHOP_F_SYN|CHOP_F_FIN))) {
      log_debug(c, "discarding chaff with no flags");
      evbuffer_free(block);
      return 0;
    }

    hdr->length = 0;
    evbuffer_drain(block, evbuffer_get_length(block));
    log_debug(c, "chaff with flags, treating length as 0");
  }

  /* SYN must occur at offset zero, may not be duplicated, and if we
     already have anything on the reassembly queue, it must come
     logically after this block. */
  if ((hdr->flags & CHOP_F_SYN) &&
      (hdr->offset > 0 ||
       (queue->next != queue &&
        ((queue->next->flags & CHOP_F_SYN) ||
         !mod32_le(hdr->offset + hdr->length, queue->next->offset))))) {
    log_warn(c, "protocol error: inappropriate SYN block");
    return -1;
  }

  /* FIN may not be duplicated and must occur logically after everything
     we've already received. */
  if ((hdr->flags & CHOP_F_FIN) && queue->prev != queue &&
      ((queue->prev->flags & CHOP_F_FIN) ||
       !mod32_le(queue->prev->offset + queue->prev->length, hdr->offset))) {
    log_warn(c, "protocol error: inappropriate FIN block");
    return -1;
  }

  /* Non-SYN/FIN must come after any SYN block presently in the queue
     and before any FIN block presently in the queue. */
  if (!(hdr->flags & (CHOP_F_SYN|CHOP_F_FIN)) && queue->next != queue &&
      (((queue->next->flags & CHOP_F_SYN) &&
        !mod32_le(queue->next->offset + queue->next->length, hdr->offset)) ||
       ((queue->prev->flags & CHOP_F_FIN) &&
        !mod32_le(hdr->offset + hdr->length, queue->prev->offset)))) {
    log_warn(c, "protocol error: inappropriate normal block");
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
      log_warn(c, "protocol error: %u byte block does not fit at offset %u",
               hdr->length, hdr->offset);
      return -1;
    }
  }

  /* This block goes before, but does not merge with, 'p'.
     Special case: if 'p' is the sentinel, we have not yet checked
     that this block goes after the last block in the list (aka p->prev). */
  if (!p->data && p->prev->data &&
      !mod32_lt(p->prev->offset + p->prev->length, hdr->offset)) {
    log_warn(c, "protocol error: %u byte block does not fit at offset %u "
                "(sentinel case)",
             hdr->length, hdr->offset);
    return -1;
  }

  q = (chop_reassembly_elt *)xzalloc(sizeof(chop_reassembly_elt));
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
    log_warn(c, "failed to append to existing buffer");
    return -1;
  }
  evbuffer_free(block);
  p->length += hdr->length;
  p->flags |= hdr->flags;

  /* Can we now combine 'p' with its successor? */
  while (p->next->data && p->offset + p->length == p->next->offset) {
    q = p->next;
    if (evbuffer_add_buffer(p->data, q->data)) {
      log_warn(c, "failed to merge buffers");
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
    log_warn(c, "failed to prepend to existing buffer");
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
      log_warn(c, "failed to merge buffers");
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
  chop_circuit_t *ckt = static_cast<chop_circuit_t *>(c);
  /* Only the first reassembly queue entry, if any, can possibly be
     ready to flush (because chop_reassemble_block ensures that there
     are gaps between all queue elements).  */
  chop_reassembly_elt *ready = ckt->reassembly_queue.next;
  if (!ready->data || ckt->recv_offset != ready->offset) {
    log_debug(c, "no data pushable to upstream yet");
    return 0;
  }

  if (!ckt->received_syn) {
    if (!(ready->flags & CHOP_F_SYN)) {
      log_debug(c, "waiting for SYN");
      return 0;
    }
    log_debug(c, "processed SYN");
    ckt->received_syn = true;
  }

  log_debug(c, "can push %lu bytes to upstream",
            (unsigned long)evbuffer_get_length(ready->data));
  if (evbuffer_add_buffer(bufferevent_get_output(c->up_buffer), ready->data)) {
    log_warn(c, "failure pushing data to upstream");
    return -1;
  }

  ckt->recv_offset += ready->length;

  if (ready->flags & CHOP_F_FIN) {
    log_assert(!ckt->received_fin);
    log_assert(ready->next == &ckt->reassembly_queue);
    ckt->received_fin = true;
    log_debug(c, "processed FIN");
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
chop_find_or_make_circuit(conn_t *conn, uint64_t circuit_id)
{
  log_assert(conn->cfg->mode == LSN_SIMPLE_SERVER);

  chop_config_t *cfg = static_cast<chop_config_t *>(conn->cfg);
  chop_circuit_table::value_type in(circuit_id, 0);
  std::pair<chop_circuit_table::iterator, bool> out = cfg->circuits.insert(in);
  circuit_t *ck;

  if (!out.second) { // element already exists
    if (!out.first->second) {
      log_debug(conn, "stale circuit");
      return 0;
    }
    ck = out.first->second;
    log_debug(conn, "found circuit to %s", ck->up_peer);
  } else {
    ck = cfg->circuit_create();
    if (!ck) {
      log_warn(conn, "failed to create new circuit");
      return -1;
    }
    if (circuit_open_upstream(ck)) {
      log_warn(conn, "failed to begin upstream connection");
      circuit_close(ck);
      return -1;
    }
    log_debug(conn, "created new circuit to %s", ck->up_peer);
    static_cast<chop_circuit_t *>(ck)->circuit_id = circuit_id;
    out.first->second = ck;
  }

  circuit_add_downstream(ck, conn);
  return 0;
}

/* Protocol methods */

chop_config_t::chop_config_t()
{
  ignore_socks_destination = true;
}

chop_config_t::~chop_config_t()
{
  if (up_address)
    evutil_freeaddrinfo(up_address);
  for (vector<struct evutil_addrinfo *>::iterator i = down_addresses.begin();
       i != down_addresses.end(); i++)
    evutil_freeaddrinfo(*i);

  /* The strings in steg_targets are not on the heap. */

  for (chop_circuit_table::iterator i = circuits.begin();
       i != circuits.end(); i++)
    if (i->second)
      circuit_close(i->second);
}

bool
chop_config_t::init(int n_options, const char *const *options)
{
  const char* defport;
  int listen_up;
  int i;

  if (n_options < 3)
    goto usage;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    this->mode = LSN_SIMPLE_CLIENT;
    listen_up = 1;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    this->mode = LSN_SOCKS_CLIENT;
    listen_up = 1;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    this->mode = LSN_SIMPLE_SERVER;
    listen_up = 0;
  } else
    goto usage;

  this->up_address = resolve_address_port(options[1], 1, listen_up, defport);
  if (!this->up_address)
    goto usage;

  /* From here on out, arguments alternate between downstream
     addresses and steg targets, if we're the client.  If we're not
     the client, the arguments are just downstream addresses. */
  for (i = 2; i < n_options; i++) {
    struct evutil_addrinfo *addr =
      resolve_address_port(options[i], 1, !listen_up, NULL);
    if (!addr)
      goto usage;
    this->down_addresses.push_back(addr);

    if (this->mode == LSN_SIMPLE_SERVER)
      continue;
    i++;
    if (i == n_options)
      goto usage;

    if (!steg_is_supported(options[i]))
      goto usage;
    this->steg_targets.push_back(options[i]);
  }
  return true;

 usage:
  log_warn("chop syntax:\n"
           "\tchop <mode> <up_address> (<down_address> [<steg>])...\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tup_address, down_address ~ host:port\n"
           "\t\ta steg target is required for each down_address,\n"
           "\t\tin client and socks mode, and forbidden otherwise.\n"
           "\t\tThe down_address list is still required in socks mode.\n"
           "Examples:\n"
           "\tstegotorus chop client 127.0.0.1:5000 "
           "192.168.1.99:11253 http 192.168.1.99:11254 skype\n"
           "\tstegotorus chop server 127.0.0.1:9005 "
           "192.168.1.99:11253 192.168.1.99:11254");
  return false;
}

struct evutil_addrinfo *
chop_config_t::get_listen_addrs(size_t n)
{
  if (this->mode == LSN_SIMPLE_SERVER) {
    if (n < this->down_addresses.size())
      return this->down_addresses[n];
  } else {
    if (n == 0)
      return this->up_address;
  }
  return 0;
}

struct evutil_addrinfo *
chop_config_t::get_target_addrs(size_t n)
{
  if (this->mode == LSN_SIMPLE_SERVER) {
    if (n == 0)
      return this->up_address;
  } else {
    if (n < this->down_addresses.size())
      return this->down_addresses[n];
  }
  return NULL;
}

circuit_t *
chop_config_t::circuit_create()
{
  chop_circuit_t *ckt = new chop_circuit_t;
  ckt->cfg = this;

  if (this->mode == LSN_SIMPLE_SERVER) {
    ckt->send_crypt = encryptor::create(s2c_key, 16);
    ckt->recv_crypt = decryptor::create(c2s_key, 16);
  } else {
    ckt->send_crypt = encryptor::create(c2s_key, 16);
    ckt->recv_crypt = decryptor::create(s2c_key, 16);
    while (!ckt->circuit_id)
      rng_bytes((uint8_t *)&ckt->circuit_id, sizeof(uint64_t));
  }
  return ckt;
}

chop_circuit_t::chop_circuit_t()
{
  this->reassembly_queue.next = &this->reassembly_queue;
  this->reassembly_queue.prev = &this->reassembly_queue;
}

chop_circuit_t::~chop_circuit_t()
{
  chop_reassembly_elt *p, *q, *queue;
  chop_circuit_table::iterator out;

  for (unordered_set<conn_t *>::iterator i = this->downstreams.begin();
       i != this->downstreams.end(); i++) {
    conn_t *conn = *i;
    conn->circuit = NULL;
    if (evbuffer_get_length(conn_get_outbound(conn)) > 0)
      conn_do_flush(conn);
    else
      conn_close(conn);
  }

  delete this->send_crypt;
  delete this->recv_crypt;

  queue = &this->reassembly_queue;
  for (q = p = queue->next; p != queue; p = q) {
    q = p->next;
    if (p->data)
      evbuffer_free(p->data);
    free(p);
  }

  if (this->cfg->mode == LSN_SIMPLE_SERVER) {
    /* The IDs for old circuits are preserved for a while (at present,
       indefinitely; FIXME: purge them on a timer) against the
       possibility that we'll get a junk connection for one of them
       right after we close it (same deal as the TIME_WAIT state in TCP). */
    chop_config_t *cfg = static_cast<chop_config_t *>(this->cfg);
    out = cfg->circuits.find(this->circuit_id);
    log_assert(out != cfg->circuits.end());
    log_assert(out->second == this);
    out->second = NULL;
  }
}

void
chop_circuit_t::add_downstream(conn_t *conn)
{
  this->downstreams.insert(conn);
  log_debug(this, "added connection <%d.%d> to %s, now %lu",
            this->serial, conn->serial, conn->peername,
            (unsigned long)this->downstreams.size());

  circuit_disarm_axe_timer(this);
}

void
chop_circuit_t::drop_downstream(conn_t *conn)
{
  this->downstreams.erase(conn);
  log_debug(this, "dropped connection <%d.%d> to %s, now %lu",
            this->serial, conn->serial, conn->peername,
            (unsigned long)this->downstreams.size());
  /* If that was the last connection on this circuit AND we've both
     received and sent a FIN, close the circuit.  Otherwise, if we're
     the server, arm a timer that will kill off this circuit in a
     little while if no new connections happen (we might've lost all
     our connections to protocol errors, or because the steg modules
     wanted them closed); if we're the client, send chaff in a bit,
     to enable further transmissions from the server. */
  if (this->downstreams.empty()) {
    if (this->sent_fin && this->received_fin) {
      if (evbuffer_get_length(bufferevent_get_output(this->up_buffer)) > 0)
        /* this may already have happened, but there's no harm in
           doing it again */
        circuit_do_flush(this);
      else
        circuit_close(this);
    } else if (this->cfg->mode == LSN_SIMPLE_SERVER) {
      circuit_arm_axe_timer(this, 5000);
    } else {
      circuit_arm_flush_timer(this, 1);
    }
  }
}

conn_t *
chop_config_t::conn_create()
{
  chop_conn_t *conn = new chop_conn_t;
  conn->cfg = this;
  if (this->mode != LSN_SIMPLE_SERVER) {
    /* XXX currently uses steg target 0 for all connections.
       Need protocol-specific listener state to fix this. */
    conn->steg = steg_new(this->steg_targets[0]);
    if (!conn->steg) {
      free(conn);
      return 0;
    }
  }
  conn->recv_pending = evbuffer_new();
  return conn;
}

chop_conn_t::chop_conn_t()
{
}

chop_conn_t::~chop_conn_t()
{
  if (this->steg)
    delete this->steg;
  if (this->must_transmit_timer)
    event_free(this->must_transmit_timer);
  evbuffer_free(this->recv_pending);
}

int
chop_conn_t::maybe_open_upstream()
{
  /* We can't open the upstream until we have a circuit ID. */
  return 0;
}

int
chop_conn_t::handshake()
{
  /* Chop has no handshake as such, but like dsteg, we need to send
     _something_ from the client on at least one of the channels
     shortly after connection, because the server doesn't know which
     connections go with which circuits till it hears from us, _and_
     it doesn't know what steganography to use.  We use a 1ms timeout
     instead of a 10ms timeout as in dsteg, because unlike there, the
     server can't even _connect to its upstream_ till it gets the
     first packet from the client. */
  if (this->cfg->mode != LSN_SIMPLE_SERVER)
    circuit_arm_flush_timer(this->circuit, 1);
  return 0;
}

int
chop_circuit_t::send()
{
  circuit_disarm_flush_timer(this);

  if (this->downstreams.empty()) {
    /* We have no connections, but we must send.  If we're the client,
       reopen our outbound connections; the on-connection event will
       bring us back here.  If we're the server, we have to just
       twiddle our thumbs and hope the client reconnects. */
    log_debug(this, "no downstream connections");
    if (this->cfg->mode != LSN_SIMPLE_SERVER)
      circuit_reopen_downstreams(this);
    else
      circuit_arm_axe_timer(this, 5000);
    return 0;
  }

  if (evbuffer_get_length(bufferevent_get_input(this->up_buffer)) == 0) {
    /* must-send timer expired and we still have nothing to say; send chaff */
    if (chop_send_chaff(this))
      return -1;
  } else {
    if (chop_send_blocks(this))
      return -1;
  }

  /* If we're at EOF, close all connections (sending first if
     necessary).  If we're the client we have to keep trying to talk
     as long as we haven't both sent and received a FIN, or we might
     deadlock. */
  if (this->sent_fin && this->received_fin) {
    for (unordered_set<conn_t *>::iterator i = this->downstreams.begin();
         i != this->downstreams.end(); i++) {
      chop_conn_t *conn = static_cast<chop_conn_t*>(*i);
      if (conn->must_transmit_timer &&
          evtimer_pending(conn->must_transmit_timer, NULL))
        must_transmit_timer_cb(-1, 0, conn);
      conn_send_eof(conn);
    }
  } else {
    if (this->cfg->mode != LSN_SIMPLE_SERVER)
      circuit_arm_flush_timer(this, 5);
  }
  return 0;
}

int
chop_circuit_t::send_eof()
{
  this->upstream_eof = true;
  return this->send();
}

int
chop_conn_t::recv()
{
  circuit_t *c;
  chop_circuit_t *ckt;
  chop_header hdr;
  struct evbuffer *block;
  size_t avail;
  uint8_t decodebuf[CHOP_MAX_DATA + CHOP_WIRE_HDR_LEN];

  if (!this->steg) {
    log_assert(this->cfg->mode == LSN_SIMPLE_SERVER);
    if (evbuffer_get_length(conn_get_inbound(this)) == 0)
      return 0; /* need more data */
    this->steg = steg_detect(this);
    if (!this->steg) {
      log_debug(this, "no recognized steg pattern detected");
      return -1;
    } else {
      log_debug(this, "detected steg pattern %s", this->steg->name());
    }
  }

  if (this->steg->receive(this, this->recv_pending))
    return -1;

  if (!this->circuit) {
    log_debug(this, "finding circuit");
    if (chop_peek_circuit_id(this->recv_pending, &hdr)) {
      log_debug(this, "not enough data to find circuit yet");
      return 0;
    }
    if (chop_find_or_make_circuit(this, hdr.ckt_id))
      return -1;
    /* If we get here and this->circuit is not set, this is a connection
       for a stale circuit: that is, a new connection made by the
       client (to draw more data down from the server) that crossed
       with a server-to-client FIN.  We can't decrypt the packet, but
       it's either chaff or a protocol error; either way we can just
       discard it.  Since we will never reply, call conn_do_flush so
       the connection will be dropped as soon as we receive an EOF. */
    if (!this->circuit) {
      evbuffer_drain(this->recv_pending,
                     evbuffer_get_length(this->recv_pending));
      conn_do_flush(this);
      return 0;
    }
  }

  c = this->circuit;
  ckt = static_cast<chop_circuit_t *>(c);
  log_debug(this, "circuit to %s", c->up_peer);

  for (;;) {
    avail = evbuffer_get_length(this->recv_pending);
    if (avail == 0)
      break;

    log_debug(this, "%lu bytes available", (unsigned long)avail);
    if (avail < CHOP_WIRE_HDR_LEN) {
      log_debug(this, "incomplete block");
      break;
    }

    if (chop_decrypt_header(ckt, this->recv_pending, &hdr))
      return -1;

    if (avail < CHOP_WIRE_HDR_LEN + GCM_TAG_LEN + hdr.length) {
      log_debug(this, "incomplete block (need %lu bytes)",
                (unsigned long)(CHOP_WIRE_HDR_LEN + GCM_TAG_LEN + hdr.length));
      break;
    }

    if (ckt->circuit_id != hdr.ckt_id) {
      log_warn(this, "protocol error: circuit id mismatch");
      return -1;
    }

    log_debug(this, "receiving block of %lu+%u bytes "
                 "[offset %u flags %04hx]",
                 (unsigned long)CHOP_WIRE_HDR_LEN + GCM_TAG_LEN,
                 hdr.length, hdr.offset, hdr.flags);

    if (evbuffer_copyout(this->recv_pending, decodebuf,
                         CHOP_WIRE_HDR_LEN + GCM_TAG_LEN + hdr.length)
        != (ssize_t)(CHOP_WIRE_HDR_LEN + GCM_TAG_LEN + hdr.length)) {
      log_warn(this, "failed to copy block to decode buffer");
      return -1;
    }
    block = evbuffer_new();
    if (!block || evbuffer_expand(block, hdr.length)) {
      log_warn(this, "allocation failure");
      return -1;
    }

    if (ckt->recv_crypt
        ->decrypt(decodebuf + 16, decodebuf + 16,
                  hdr.length + CHOP_WIRE_HDR_LEN + GCM_TAG_LEN - 16,
                  decodebuf, 16)) {
      log_warn(this, "MAC verification failure");
      evbuffer_free(block);
      return -1;
    }

    if (evbuffer_add(block, decodebuf + CHOP_WIRE_HDR_LEN, hdr.length)) {
      log_warn(this, "failed to transfer block to reassembly queue");
      evbuffer_free(block);
      return -1;
    }

    if (evbuffer_drain(this->recv_pending,
                       CHOP_WIRE_HDR_LEN + GCM_TAG_LEN + hdr.length)) {
      log_warn(this, "failed to consume block from wire");
      evbuffer_free(block);
      return -1;
    }

    if (chop_reassemble_block(c, block, &hdr)) {
      evbuffer_free(block);
      return -1;
    }
  }

  if (chop_push_to_upstream(c))
    return -1;

  /* It may have now become possible to send queued data. */
  if (evbuffer_get_length(bufferevent_get_input(c->up_buffer)))
    c->send();

  return 0;
}

int
chop_conn_t::recv_eof()
{
  circuit_t *c = this->circuit;

  /* EOF on a _connection_ does not mean EOF on a _circuit_.
     EOF on a _circuit_ occurs when chop_push_to_upstream processes a FIN.
     We should only drop the connection from the circuit if we're no
     longer sending in the opposite direction.  Also, we should not
     drop the connection if its must-transmit timer is still pending.  */
  if (c) {
    chop_circuit_t *ckt = static_cast<chop_circuit_t *>(c);

    if (evbuffer_get_length(conn_get_inbound(this)) > 0)
      if (this->recv())
        return -1;

    if ((ckt->sent_fin || this->no_more_transmissions) &&
        (!this->must_transmit_timer ||
         !evtimer_pending(this->must_transmit_timer, NULL)))
      circuit_drop_downstream(c, this);
  }
  return 0;
}

void
chop_conn_t::expect_close()
{
  /* do we need to do something here? */
}

void
chop_conn_t::cease_transmission()
{
  this->no_more_transmissions = true;
  conn_do_flush(this);
}

void
chop_conn_t::close_after_transmit()
{
  this->no_more_transmissions = true;
  conn_do_flush(this);
}

void
chop_conn_t::transmit_soon(unsigned long milliseconds)
{
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = milliseconds * 1000;

  if (!this->must_transmit_timer)
    this->must_transmit_timer = evtimer_new(this->cfg->base,
                                            must_transmit_timer_cb, this);
  evtimer_add(this->must_transmit_timer, &tv);
}
