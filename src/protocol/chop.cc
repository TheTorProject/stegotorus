/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include <algorithm>
#include <map>

#include <sstream>
#include <string>
#include <stdint.h>

#include <algorithm>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/util.h>

#include <yaml-cpp/yaml.h>

#include "util.h"
#include "crypt.h"
#include "chop_handshaker.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"

#include "chop_conn.h"
#include "chop_config.h"
#include "chop_circuit.h"

/* The chopper is the core StegoTorus protocol implementation.
   For its design, see doc/chopper.txt.  Note that it is still
   being implemented, and may change incompatibly.  */

#define MAX_CONN_PER_CIRCUIT 8

using std::unordered_set;
using std::vector;
using std::min;

using namespace chop_blk;

namespace chop_protocol {

chop_circuit_t::chop_circuit_t(bool retransmit)
  : tx_queue(retransmit), avg_desirable_size(0), avg_available_size(0),
    number_of_room_requests(0)
{
}

chop_circuit_t::~chop_circuit_t()
{
  delete send_crypt;
  delete send_hdr_crypt;
  delete recv_crypt;
  delete recv_hdr_crypt;
}

void
chop_circuit_t::close()
{
  if (!sent_fin || !received_fin || !upstream_eof) {
    log_warn(this, "destroying active circuit: fin%c%c eof%c ds=%lu",
             sent_fin ? '+' : '-', received_fin ? '+' : '-',
             upstream_eof ? '+' : '-',
             (unsigned long)downstreams.size());
  }

  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;
    conn->upstream = NULL;
    conn->do_flush();
  }
  downstreams.clear();

  // The IDs for old circuits are preserved for a while (at present,
  // indefinitely; FIXME: purge them on a timer) against the
  // possibility that we'll get a junk connection for one of them
  // right after we close it (same deal as the TIME_WAIT state in
  // TCP).  Note that we can hit this case for the *client* if the
  // cover protocol includes a mandatory reply to every client message
  // and the hidden channel closed s->c before c->s: the circuit will
  // get destroyed on the client side after the c->s FIN, and the
  // mandatory reply will be to a stale circuit.
  chop_circuit_table::iterator out;
  log_debug(this,"deleting circuit %u from the table", circuit_id);
  out = config->circuits.find(circuit_id);
  log_assert(out != config->circuits.end());
  log_assert(out->second == this);
  out->second = NULL;

  circuit_t::close();
}

config_t *
chop_circuit_t::cfg() const
{
  return config;
}

void
chop_circuit_t::add_downstream(chop_conn_t *conn)
{
  log_assert(conn);
  log_assert(!conn->upstream);
  conn->upstream = this;
  downstreams.insert(conn);

  log_debug(this, "added connection <%d.%d> to %s, now %lu",
            serial, conn->serial, conn->peername,
            (unsigned long)downstreams.size());

  this->disarm_axe_timer();
}

void
chop_circuit_t::add_downstream(conn_t *cn)
{
  add_downstream(dynamic_cast<chop_conn_t *>(cn));
}

void
chop_circuit_t::drop_downstream(chop_conn_t *conn)
{
  log_assert(conn);
  log_assert(conn->upstream == this);

  conn->upstream = NULL;
  downstreams.erase(conn);

  log_debug(this, "dropped connection <%d.%d> to %s, now %lu",
            serial, conn->serial, conn->peername,
            (unsigned long)downstreams.size());
  // If that was the last connection on this circuit AND we've both
  // received and sent a FIN, close the circuit.  Otherwise, if we're
  // the server, arm a timer that will kill off this circuit in a
  // little while if no new connections happen (we might've lost all
  // our connections to protocol errors, or because the steg modules
  // wanted them closed); if we're the client, send chaff in a bit,
  // to enable further transmissions from the server.
  if (downstreams.empty()) {
    if (sent_fin && received_fin) {
      do_flush();
    } else if (config->mode == LSN_SIMPLE_SERVER) {
      arm_axe_timer(axe_interval());
    } else {
      arm_flush_timer(flush_interval());
    }
  }
}

void
chop_circuit_t::drop_downstream(conn_t *cn)
{
  drop_downstream(dynamic_cast<chop_conn_t *>(cn));
}

uint32_t
chop_circuit_t::axe_interval() {
    // This function must always return a number which is larger than
    // the maximum possible number that *our peer's* flush_interval()
    // could have returned; otherwise, we might axe the connection when
    // it was just that there was nothing to say for a while.
    // For simplicity's sake, right now we hardwire this to be 30 minutes.

    //However, this approach expose server to a simple and powerful
    //DoS attack: do 10^10 times: asks for 1GB file drop the upstream connection,
    //soon the server is out of memory cause it keeps the content in the evbuff
    //This should depends on global state of memory but as a simple rule of thumb, 
    //for now under 
    // 0        30 min
    // 100K     29 min
    // 1MB      5  min
    // 10MB     1  min
    // However this should be only applied when we get enough dead cycle that
    // indicates the client is no longer interested in the content
    // 30min - rng(log(size(0), cycles)
    const static unsigned int max_idle_min = 30;
    if (!dead_cycles)
      return max_idle_min * 60 * 1000;

    //Anti dos measures
    size_t memory_consumed = evbuffer_get_length(bufferevent_get_input(up_buffer));

    unsigned int max_penalty_mins = std::min(max_idle_min-1, ui64_log2(memory_consumed)) + 2;
    unsigned int penalty_mins = rng_range_geom(max_penalty_mins, std::min((unsigned int)(max_penalty_mins - 1), dead_cycles));
    //dead_cycles > 0 and this never become equal to max_penalty 

    return std::max((unsigned int)(max_idle_min - penalty_mins) * 60 * 1000, 100u);

}
  
uint32_t
chop_circuit_t::flush_interval() {
    // 10*60*1000 lies between 2^19 and 2^20.
    uint32_t shift = std::max(1u, std::min(19u, dead_cycles));
    uint32_t xv = std::max(1u, std::min(10u * 60 * 1000, 1u << shift));
    //TODO: this needs to be formalised but the original formula sometimes gives 1min
    //that is t otally unacceptable
    if (dead_cycles == 0)
      return 100;

    return rng_range_geom(20 * 60 * 1000, xv) + 100;
  }

int
chop_circuit_t::send()
{
  disarm_flush_timer();

  //First we check if there's steg data that we need to send
  if (send_all_steg_data())
    {
      log_debug("Error in transmiting steg protocol data");
    }

  struct evbuffer *xmit_pending = bufferevent_get_input(up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  size_t avail0 = avail;
  bool no_target_connection = false;

  if (downstreams.empty()) {
    log_debug(this, "no downstream connections");
    no_target_connection = true;
  } else {
    bool did_retransmit = false;
    if (avail == 0 && !(upstream_eof && !sent_fin) && config->retransmit) {
      // Consider retransmission.
      evbuffer *block = 0;
      for (transmit_queue::iterator i = tx_queue.begin();
           i != tx_queue.end();
           ++i) {
        transmit_elt &el = *i;
        size_t lo = MIN_BLOCK_SIZE + el.hdr.dlen();
        size_t room;
        chop_conn_t *conn = pick_connection(lo, lo, &room);
        if (!conn)
          continue;
        log_assert(lo <= room);

        if (!block)
          block = evbuffer_new();
        if (!block)
          log_abort("memory allocation failed");
        if (tx_queue.retransmit(el, room - lo, block,
                                *send_hdr_crypt, *send_crypt) ||
            conn->send(block)) {
          evbuffer_free(block);
          return -1;
        }

        char fallbackbuf[4];
        log_debug(conn, "retransmitted block %u <d=%lu p=%lu f=%s>",
                  el.hdr.seqno(),
                  (unsigned long)el.hdr.dlen(),
                  (unsigned long)el.hdr.plen(),
                  opname(el.hdr.opcode(), fallbackbuf));

        if (config->trace_packets)
          fprintf(stderr,
                  "T:%.4f: ckt %u <ntp %u outq %lu>: "
                  "resend %lu <d=%lu p=%lu f=%s>\n",
                  log_get_timestamp(), this->serial,
                  this->recv_queue.window(),
                  (unsigned long)evbuffer_get_length(
                                bufferevent_get_input(this->up_buffer)),
                  (unsigned long)el.hdr.seqno(),
                  (unsigned long)el.hdr.dlen(),
                  (unsigned long)el.hdr.plen(),
                  opname(el.hdr.opcode(), fallbackbuf));

        evbuffer_free(block);
        did_retransmit = true;
        break;
      }
    }

    if (!did_retransmit && !tx_queue.full())
    // Send at least one block, even if there is no real data to send.
      do {
        log_debug(this, "%lu bytes to send", (unsigned long)avail);
        size_t blocksize;
        chop_conn_t *target = pick_connection(avail, 0, &blocksize);
        if (!target) {
          // this is not an error; it can happen e.g. when the server has
          // something to send immediately and the client hasn't spoken yet
          log_debug(this, "no target connection available");
          no_target_connection = true;
          break;
        }

        if (send_targeted(target, blocksize))
          return -1;

        avail = evbuffer_get_length(xmit_pending);
      } while (avail > 0);
  }

  if (avail0 == avail) { //no forward progress
    if (avail > 0) {//we have something new to send but we made no forward progress 
      dead_cycles++;
      log_debug(this, "%u dead cycles", dead_cycles);
    }
    // If we're the client and we had no target connection, try
    // reopening new connections.  If we're the server, we have to
    // just twiddle our thumbs and hope the client does that.

    // Vmon: the steg mod on the server should close the  connections which provide zero room,
    // this way, if the client has made too many connections will get the opportunity
    // to open a new one. If not then it is a deficiency/bug in the design of the steg mod.
    if (no_target_connection) {
      log_debug(this, "number of open connections on this circuit %u, golobally %u", (unsigned int)downstreams.size(), (unsigned int) conn_count());
      if (config->mode != LSN_SIMPLE_SERVER &&
          (int)downstreams.size() < min(MAX_CONN_PER_CIRCUIT, ((int)(MAX_GLOBAL_CONN_COUNT - conn_count() + (int)circuit_count() - 1)/(int)circuit_count()))) //min(8, and ceilling of (MAX - count)/no of circ) 
        circuit_reopen_downstreams(this);
      else {
        log_debug(this,"no more connection available at this time");
        arm_axe_timer(axe_interval());
      }
    }
  }

  return check_for_eof();
}

int
chop_circuit_t::send_all_steg_data()
{

  if (downstreams.empty()) {
      log_debug(this, "no downstream connections");
      return 0;
  }

  // you might think that it makes sense to check if there is any steg data to be sent
  //otherwise we can just return. but we can't do that cause each connection has
  //its own steg module and some of the steg module might have steg data and others might
  //not

  bool no_target_connection = true;

  //TODO: Instead of re-implementing pick connection here I should 
  //adopt it so it can works both for send and send steg.
  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *target = *i;

    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!target->steg) {
      log_debug(target, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!target->connected) {
      log_debug(target, "offers 0 bytes (not connected)");
      continue;
    }

    size_t avail0;

    //Now we check if the protocol_data has any data
    size_t avail = evbuffer_get_length(target->steg->cfg()->protocol_data_out);
    //we try to send all data
    //we don't send random block or retransmit from the transmit
    //queue because we are called by the this->send which will
    //send those anyways
    while(avail > 0) {
      size_t desired;
      if (avail > SECTION_LEN)
        desired = SECTION_LEN;
      else
        desired = avail;

      desired += MIN_BLOCK_SIZE;

      size_t lo = MIN_BLOCK_SIZE + (desired == MIN_BLOCK_SIZE ? 0 : 1);

      log_debug(this, "target block size %lu bytes", (unsigned long)desired);

      log_debug(this, "%lu bytes to send", (unsigned long)avail);
      size_t shake = target->sent_handshake ? 0 : HANDSHAKE_LEN;
      size_t room = target->steg->transmit_room(desired + shake, lo + shake,
                                                  MAX_BLOCK_SIZE + shake);
      if (room != 0) {
        if (room < lo + shake || room >= MAX_BLOCK_SIZE + shake)
          log_abort(target, "steg size request (%lu) out of range [%lu, %lu]",
                    (unsigned long)room,
                    (unsigned long)(lo + shake),
                    (unsigned long)(MAX_BLOCK_SIZE + shake));

        log_debug(target, "offers %lu bytes (%s)", (unsigned long)room,
                  target->steg->cfg()->name());

        if (send_targeted_steg_data(target, room))
          return -1;
      }
      else {
        log_debug(target, "offers 0 bytes (%s)",
                  target->steg->cfg()->name());
      }

      avail0 = avail;
      avail = evbuffer_get_length(target->steg->cfg()->protocol_data_out);

      if (avail0 == avail) { // no forward progress
        dead_cycles++;
        log_debug(this, "%u dead cycles", dead_cycles);
        break;
      }
      else {
        no_target_connection = false;
      }
    } //while(avail > 0)
  } //for all targets
  
  (void) no_target_connection;
  // If we're the client and we had no target connection, try
  // reopening new connections.  If we're the server, we have to
  // just twiddle our thumbs and hope the client does that.
  // if (no_target_connection) {
  //   if (config->mode != LSN_SIMPLE_SERVER &&
  //       downstreams.size() < 64) {
  //     log_debug("number of open connections %u", (unsigned int) downstreams.size());
  //     circuit_reopen_downstreams(this);
  //   }
  //   else {
  //     log_debug("number of open connections %u", (unsigned int) downstreams.size());
  //     circuit_arm_axe_timer(this, axe_interval());
  //   }
  // }

  return 0;
}


int
chop_circuit_t::send_eof()
{
  /* N.B. "read_eof" and "write_eof" are relative to _upstream_, and
   therefore may appear to be backward relative to the function names
   here.  I find this less confusing than having them appear to be
   backward relative to the shutdown() calls and buffer drain checks,
   here and in network.cc. */

  this->pending_read_eof = true;
  if (this->socks_state) {
    log_debug(this, "EOF during SOCKS phase");
    this->close();
  } else {
    upstream_eof = true;
    if (send()) {
      log_info(this, "error during transmit");
      this->close();
      return -1;
    }
  }

  return 0;
  
}

//TODO check if send_special can be used steg data communication
//instead of send_all_steg_data
int
chop_circuit_t::send_special(opcode_t f, struct evbuffer *payload)
{
  if (!payload)
    payload = evbuffer_new();
  if (!payload) {
    log_warn(this, "memory allocation failure");
    return -1;
  }

  size_t d = evbuffer_get_length(payload);
  log_assert(d <= SECTION_LEN);

  if (tx_queue.full()) {
    log_warn(this, "transmit queue full, cannot send");
    return -1;
  }

  size_t blocksize = 0;
  size_t p;
  chop_conn_t *conn = pick_connection(d, d, &blocksize);
  if (!conn || blocksize < MIN_BLOCK_SIZE + d) {
    char fallbackbuf[4];
    log_debug("no usable connection for special block "
             "(opcode %s, need %lu bytes, have %lu)",
             opname(f, fallbackbuf), (unsigned long)(d + MIN_BLOCK_SIZE),
             (unsigned long)blocksize);
    conn = 0;
    p = 0;
  } else {
    p = blocksize - (d + MIN_BLOCK_SIZE);
  }

  // Regardless of whether we were able to find a connection right now,
  // enqueue the block for transmission when possible.
  // The transmit queue takes ownership of 'payload' at this point.
  uint32_t seqno = tx_queue.enqueue(f, payload, p);

  // Not having a connection to use right now does not constitute a failure.
  if (!conn)
    return 0;

  struct evbuffer *block = evbuffer_new();
  if (!block) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }
  if (tx_queue.transmit(seqno, block, *send_hdr_crypt, *send_crypt)) {
    log_warn(conn, "encryption failure for block %u", seqno);
    evbuffer_free(block);
    return -1;
  }

  if (conn->send(block)) {
    evbuffer_free(block);
    return -1;
  }
  evbuffer_free(block);

  char fallbackbuf[4];
  log_debug(conn, "transmitted block %u <d=%lu p=%lu f=%s>",
            seqno, (unsigned long)d, (unsigned long)p,
            opname(f, fallbackbuf));

  if (config->trace_packets)
    fprintf(stderr,
            "T:%.4f: ckt %u <ntp %u outq %lu>: "
            "send %lu <d=%lu p=%lu f=%s>\n",
            log_get_timestamp(), this->serial,
            this->recv_queue.window(),
            (unsigned long)evbuffer_get_length(
                              bufferevent_get_input(this->up_buffer)),
            (unsigned long)seqno,
            (unsigned long)d,
            (unsigned long)p,
            opname(f, fallbackbuf));

  if (f == op_FIN) {
    sent_fin = true;
    read_eof = true;
  }
  if ((f == op_DAT && d > 0) || f == op_FIN) {
    // We are making forward progress if we are _either_ sending or
    // receiving data.
    dead_cycles = 0;
    //vmon: We are making progress, there is no reason to keep the supposedly scheduled
    //death hour for this circuit. It might connected and working for hours.
    disarm_axe_timer();
  }
  
  return 0;
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn)
{
  //Priority with steg data
  bool steg_data_available = false;
  size_t avail = evbuffer_get_length(conn->steg->cfg()->protocol_data_out);
  if (avail > 0)
    steg_data_available = true;
  else
    avail = evbuffer_get_length(bufferevent_get_input(up_buffer));

  if (avail == 0 && !(upstream_eof && !sent_fin) && config->retransmit) {
    // Consider retransmission if we have nothing new to send.
    evbuffer *block = evbuffer_new();
    if (!block)
      log_abort("memory allocation failed");
    for (transmit_queue::iterator i = tx_queue.begin();
         i != tx_queue.end();
         ++i) {
      transmit_elt &el = *i;
      size_t lo = MIN_BLOCK_SIZE + el.hdr.dlen();
      size_t hi = MAX_BLOCK_SIZE;
      if (!conn->sent_handshake) {
        lo += HANDSHAKE_LEN;
        hi += HANDSHAKE_LEN;
      }

      size_t room = conn->steg->transmit_room(lo, lo, hi);
      if (lo <= room && room <= hi &&
          !tx_queue.retransmit(el, room - lo, block,
                               *send_hdr_crypt, *send_crypt)) {
        if (conn->send(block)) {
          evbuffer_free(block);
          return -1;
        }
        evbuffer_free(block);

        char fallbackbuf[4];
        log_debug(conn, "retransmitted block %u <d=%lu p=%lu f=%s>",
                  el.hdr.seqno(),
                  (unsigned long)el.hdr.dlen(),
                  (unsigned long)el.hdr.plen(),
                  opname(el.hdr.opcode(), fallbackbuf));

        if (config->trace_packets)
          fprintf(stderr,
                  "T:%.4f: ckt %u <ntp %u outq %lu>: "
                  "resend %lu <d=%lu p=%lu f=%s>\n",
                  log_get_timestamp(), this->serial,
                  this->recv_queue.window(),
                  (unsigned long)evbuffer_get_length(
                              bufferevent_get_input(this->up_buffer)),
                  (unsigned long)el.hdr.seqno(),
                  (unsigned long)el.hdr.dlen(),
                  (unsigned long)el.hdr.plen(),
                  opname(el.hdr.opcode(), fallbackbuf));

        return 0;
      }
    }
  }
      
  if (avail > SECTION_LEN)
    avail = SECTION_LEN;
  avail += MIN_BLOCK_SIZE;

  // If we have any data to transmit, ensure we do not send a block
  // that contains no data at all.
  size_t lo = MIN_BLOCK_SIZE + (avail == MIN_BLOCK_SIZE ? 0 : 1);

  // If this connection has not yet sent a handshake, it will need to.
  size_t hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += HANDSHAKE_LEN;
    hi += HANDSHAKE_LEN;
    avail += HANDSHAKE_LEN;
  }

  size_t room = conn->steg->transmit_room(avail, lo, hi);
  if (room == 0)
    log_abort(conn, "must send but cannot send");
  if (room < lo || room >= hi)
    log_abort(conn, "steg size request (%lu) out of range [%lu, %lu]",
              (unsigned long)room, (unsigned long)lo, (unsigned long)hi);

  log_debug(conn, "requests %lu bytes (%s)", (unsigned long)room,
            conn->steg->cfg()->name());

  return steg_data_available ? 
    send_targeted_steg_data(conn, room) :
    send_targeted(conn, room);
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn, size_t blocksize)
{
  size_t lo = MIN_BLOCK_SIZE, hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += HANDSHAKE_LEN;
    hi += HANDSHAKE_LEN;
  }
  log_assert(blocksize >= lo && blocksize <= hi);

  struct evbuffer *xmit_pending = bufferevent_get_input(up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  opcode_t op = op_DAT;
  
  //The original code 
  /*if (avail > blocksize - lo)
    avail = blocksize - lo;
    else if (avail > SECTION_LEN)
    avail = SECTION_LEN;*/

  if (avail > blocksize - lo || avail > SECTION_LEN)
    avail = min(blocksize - lo, SECTION_LEN);
  else if (upstream_eof && !sent_fin)
    // this block will carry the last byte of real data to be sent in
    // this direction; mark it as such
    op = op_FIN;

  return send_targeted(conn, avail, (blocksize - lo) - avail,
                       op, xmit_pending);
}

int
chop_circuit_t::send_targeted_steg_data(chop_conn_t *conn, size_t blocksize)
{
  size_t lo = MIN_BLOCK_SIZE, hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += HANDSHAKE_LEN;
    hi += HANDSHAKE_LEN;
  }
  log_assert(blocksize >= lo && blocksize <= hi);

  size_t avail = evbuffer_get_length(conn->steg->cfg()->protocol_data_out);
  opcode_t op = op_STEG0;

  if (avail > blocksize - lo || avail > SECTION_LEN)
    avail = min(blocksize - lo, SECTION_LEN);
  else if (upstream_eof && !sent_fin)
    // this block will carry the last byte of real data to be sent in
    // this direction; mark it as such
    op = op_STEG_FIN;

  return send_targeted(conn, avail, (blocksize - lo) - avail,
                       op, conn->steg->cfg()->protocol_data_out);
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn, size_t d, size_t p, opcode_t f,
                              struct evbuffer *payload)
{
  log_assert(payload || d == 0);
  log_assert(d <= SECTION_LEN);
  log_assert(p <= SECTION_LEN);

  if (tx_queue.full()) {
    log_warn(conn, "transmit queue full, cannot send");
    return -1;
  }

  struct evbuffer *data = evbuffer_new();
  if (!data) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }

  if (evbuffer_remove_buffer(payload, data, d) != (int)d) {
    log_warn(conn, "failed to extract payload");
    evbuffer_free(data);
    return -1;
  }

  // The transmit queue takes ownership of 'data' at this point.
  uint32_t seqno = tx_queue.enqueue(f, data, p);

  struct evbuffer *block = evbuffer_new();
  if (!block) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }
  if (tx_queue.transmit(seqno, block, *send_hdr_crypt, *send_crypt)) {
    log_warn(conn, "encryption failure for block %u", seqno);
    evbuffer_free(block);
    return -1;
  }

  if (conn->send(block)) {
    evbuffer_free(block);
    return -1;
  }
  evbuffer_free(block);

  //if we don't do retransmit we need to remove the block
  //from the queue not make full. because the only way that
  //ACK remove lost payload is by retransmission.

  char fallbackbuf[4];
  log_debug(conn, "transmitted block %u <d=%lu p=%lu f=%s>",
            seqno, (unsigned long)d, (unsigned long)p,
            opname(f, fallbackbuf));

  if (config->trace_packets) {
    fprintf(stderr,
            "T:%.4f: ckt %u <ntp %u outq %lu>: "
            "send %lu <d=%lu p=%lu f=%s>\n",
            log_get_timestamp(), this->serial,
            this->recv_queue.window(),
            (unsigned long)evbuffer_get_length(
                              bufferevent_get_input(this->up_buffer)),
            (unsigned long)seqno,
            (unsigned long)d,
            (unsigned long)p,
            opname(f, fallbackbuf));
    config->total_transmited_data_bytes += d;
    log_debug(this, "efficiency: %f", config->total_transmited_data_bytes/(double)(config->total_transmited_cover_bytes));
  }
  if (f == op_FIN || f == op_STEG_FIN) {
    sent_fin = true;
    read_eof = true;
  }
  if ((f == op_DAT && d > 0) || 
      (f == op_STEG0 && d > 0) ||
      f == op_FIN ||
      f == op_STEG_FIN) {
    // We are making forward progress if we are _either_ sending or
    // receiving data.
    dead_cycles = 0;
    //vmon: We are making progress, there is no reason to keep the supposedly scheduled
    //death hour for this circuit. It might connected and working for hours.
    disarm_axe_timer();
  }
  return 0;
}

// N.B. 'desired' is the desired size of the _data section_, and
// 'blocksize' on output is the size to make the _entire block_.
chop_conn_t *
chop_circuit_t::pick_connection(size_t desired, size_t minimum,
                                size_t *blocksize)
{
  size_t maxbelow = 0;
  size_t minabove = MAX_BLOCK_SIZE + 1;
  chop_conn_t *targbelow = 0;
  chop_conn_t *targabove = 0;

  log_assert(minimum <= SECTION_LEN);

  if (desired > SECTION_LEN)
    desired = SECTION_LEN;

  // If we have any data to transmit, ensure we do not send a block
  // that contains no data at all.
  if (desired > 0 && minimum == 0)
    minimum = 1;

  desired += MIN_BLOCK_SIZE;
  minimum += MIN_BLOCK_SIZE;

  log_debug(this, "target block size %lu bytes", (unsigned long)desired);

  // Find the best fit for the desired transmission from all the
  // outbound connections' transmit rooms.
  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;

    //Keeping track of connection life length
    log_debug(conn, "has been connected for %lu secs", (unsigned long)difftime(time(0), conn->creation_time));
    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!conn->steg) {
      log_debug(conn, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!conn->connected) {
      log_debug(conn, "offers 0 bytes (not connected)");
      continue;
    }

    size_t shake = conn->sent_handshake ? 0 : HANDSHAKE_LEN;
    size_t room = conn->steg->transmit_room(desired + shake,
                                            minimum + shake,
                                            MAX_BLOCK_SIZE + shake);
    if (room == 0) {
      log_debug(conn, "offers 0 bytes (%s)",
        conn->steg->cfg()->name());
      continue;
    }

    if (room < minimum + shake || room >= MAX_BLOCK_SIZE + shake)
      log_abort(conn, "steg size request (%lu) out of range [%lu, %lu]",
                (unsigned long)room,
                (unsigned long)(minimum + shake),
                (unsigned long)(MAX_BLOCK_SIZE + shake));

    log_debug(conn, "offers %lu bytes (%s)", (unsigned long)room,
              conn->steg->cfg()->name());

    //When we are here it means that our offer went through
    
    //for debug reason only
    if (config->trace_packets) {
        avg_desirable_size += (-avg_desirable_size + (desired+shake))/((double)(number_of_room_requests+1));
        avg_available_size += (-avg_available_size + (room))/((double)(number_of_room_requests+1));
        number_of_room_requests++;

        log_debug(this, "no req: %lu avg des: %f avg act: %f", number_of_room_requests, avg_desirable_size, avg_available_size);
    }
    
    if (room >= desired + shake) {
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
  }

  log_debug(this, "minabove %lu for <%u.%u> maxbelow %lu for <%u.%u>",
            (unsigned long)minabove, serial, targabove ? targabove->serial :0,
            (unsigned long)maxbelow, serial, targbelow ? targbelow->serial :0);

  // If we have a connection that can take all the data, use it.
  // Otherwise, use the connection that can take as much of the data
  // as possible.  As a special case, if no connection can take data,
  // targbelow, targabove, maxbelow, and minabove will all still have
  // their initial values, so we'll return NULL and set blocksize to 0,
  // which callers know how to handle.
  if (targabove) {
    *blocksize = minabove;
    return targabove;
  } else {
    *blocksize = maxbelow;
    return targbelow;
  }
}

/**
     checks the steg module of all connections to see if they have
     protocol data to send
     
     @return the first connection whose steg has data to send
*/
//inline because otherwise gcc will complain about the unused function
//The function which needs to check if there is on steg data on
//each steg is chop_circuit_t::send_all_steg_data but it does the check
//on conn by conn basis and send immediately (does this connection has
// steg data? then send it and then check next connection instead of
// search all connection again). However, the function might be
// useful in future
inline chop_conn_t* chop_circuit_t::check_for_steg_protocol_data()
{
  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;

    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!conn->steg) {
      log_debug(conn, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!conn->connected) {
      log_debug(conn, "offers 0 bytes (not connected)");
      continue;
    }

    //Now we check if the protocol_data has any data
    if (evbuffer_get_length(conn->steg->cfg()->protocol_data_out))
        return conn;

  }

  //nothing to send
  return NULL;

}


int
chop_circuit_t::maybe_send_ack()
{
  // Send acks aggressively if we are experiencing dead cycles *and*
  // there are blocks on the receive queue.  Otherwise, send them only
  // every 64 blocks received.  This heuristic will probably need
  // adjustment.
  
  //If we don't retransmit we shouldn't send ACK either because it will consume
  //all the channel if a block is lost
  if (!config->retransmit)
    return 0;
  log_debug(this, "considering ACK");
  if (recv_queue.window() - last_acked < 32 &&
      (!dead_cycles || recv_queue.empty()))
    {
      log_debug(this, "back log size only %u, not sending ACK", recv_queue.window() - last_acked);
      return 0;
    }

  evbuffer *ackp = recv_queue.gen_ack();
  if (log_do_debug()) {
    std::ostringstream ackdump;
    debug_ack_contents(ackp, ackdump);
    log_debug(this, "sending ACK: %s", ackdump.str().c_str());
  }
  last_acked = recv_queue.window();
  return send_special(op_ACK, ackp);
}

// Some blocks are to be processed immediately upon receipt.
/* conn is needed to have access to the steg module while the circuit is
   processing the queue, in the event that op_STEGx is op, then it is the 
   steg module that should be able to process it.
*/

int
chop_circuit_t::recv_block(uint32_t seqno, opcode_t op, 
                           evbuffer *data, steg_config_t *steg_cfg)
{
  switch (op) {
  case op_DAT:
  case op_FIN:
  case op_STEG0:   // steganography modules
  case op_STEG_FIN:

    // No special handling required.
    goto insert;

  case op_RST:
    // Remote signaled a protocol error.  Disconnect.
    log_info(this, "received RST; disconnecting circuit");
    recv_eof();
    evbuffer_free(data);
    goto zap;

  case op_ACK:
    if (log_do_debug()) {
      std::ostringstream ackdump;
      debug_ack_contents(data, ackdump);
      log_debug(this, "received ACK: %s", ackdump.str().c_str());
    }
    if (tx_queue.process_ack(data))
      log_warn(this, "protocol error: invalid ACK payload");
    //The upstream data always has priority but there are occasions that 
    //retransmitting is crucial for processing of the data 
    // here is a place to force retransmission, even if upstream data 
    // are coming
    retransmit();
    goto zap;

  case op_XXX:
  default:
    char fallbackbuf[4];
    log_warn(this, "protocol error: unsupported block opcode %s",
             opname(op, fallbackbuf));
    evbuffer_free(data);
    goto zap;
  }

 zap:
  // Block has been consumed; fill in the hole in the receive queue.
  op = op_DAT;
  data = evbuffer_new();

 insert:
  recv_queue.insert(seqno, op, data, steg_cfg);
  return 0;
}

int
chop_circuit_t::process_queue()
{
  reassembly_elt blk;
  unsigned int count = 0;
  bool pending_fin = false;
  bool pending_error = false;
  bool sent_error = false;
  while ((blk = recv_queue.remove_next()).data) {
    switch (blk.op) {
    case op_FIN:
      if (received_fin) {
        log_info(this, "protocol error: duplicate FIN");
        pending_error = true;
        break;
      }
      log_debug(this, "received FIN");
      pending_fin = true;
      // fall through - block may have data
    case op_DAT:
      if (evbuffer_get_length(blk.data)) {
        if (received_fin) {
          log_info(this, "protocol error: data after FIN");
          pending_error = true;
        } else {
          // We are making forward progress if we are _either_ sending or
          // receiving data.
          if (evbuffer_get_length(blk.data) > 0) {
            dead_cycles = 0;
            //vmon: We are making progress, there is no reason to keep the supposedly scheduled
            //death hour for this circuit. It might connected and working for hours.
            disarm_axe_timer();
          }

          log_debug(this, "writing into upstream buffer");
          if (this->write_eof)
            log_abort(this, "writing into upstream buffer after eof?");
          if (evbuffer_add_buffer(bufferevent_get_output(up_buffer),
                                  blk.data)) {
            log_warn(this, "buffer transfer failure");
            pending_error = true;
          }
        }
      }
      break;

    case op_STEG_FIN:
      if (received_fin) {
        log_info(this, "protocol error: duplicate FIN");
        pending_error = true;
        break;
      }
      log_debug(this, "received (STEG) FIN");
      pending_fin = true;
      // fall through - block may have data
    case op_STEG0:
      //write it to steg protocol data
      //FIX ME I need to check if the conn is still 
      //alive/valid
      if (evbuffer_get_length(blk.data))
        evbuffer_add_buffer(((steg_config_t*)blk.steg_cfg)->protocol_data_in, blk.data);
      
      //now ask the steg to process the data
      ((steg_config_t*)blk.steg_cfg)->process_protocol_data();
      //if steg needs to reply to the data it writes it to the same 
      //buffer and we need to send them
      //if (evbuffer_get_length(((steg_config_t*)blk.steg_cfg)->protocol_data_out))
        send();
      break;
      
    // no other opcodes should get this far
    default:
      char fallbackbuf[4];
      log_abort("f=%s block should never appear on receive queue",
                opname(blk.op, fallbackbuf));
    }

    evbuffer_free(blk.data);

    if (pending_fin && !received_fin) {
      recv_eof();
      received_fin = true;
    }
    if (pending_error && !sent_error) {
      // there's no point sending an RST in response to an RST or a
      // duplicate FIN
      if (blk.op != op_RST && blk.op != op_FIN && blk.op != op_STEG_FIN)
        send_special(op_RST, 0);
      sent_error = true;
    }
    count++;
  }

  log_debug(this, "processed %u blocks", count);
  if (sent_error)
    return -1;

  if (maybe_send_ack())
    return -1;

  // It may have become possible to send queued data or a FIN.
  if (evbuffer_get_length(bufferevent_get_input(up_buffer))
      || (upstream_eof && !sent_fin))
    return send();

  return check_for_eof();
}

int
chop_circuit_t::check_for_eof()
{
  // If we're at EOF both ways, close all connections, sending first
  // if necessary.
  if (sent_fin && received_fin) {
    log_debug(this, "sent and received FIN");
    disarm_flush_timer();
    for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
         i != downstreams.end(); i++) {
      chop_conn_t *conn = *i;
      if (conn->must_send_p())
        conn->send();
      conn->send_eof();
    }
  }

  // If we're the client we have to keep trying to talk as long as we
  // haven't both sent and received a FIN, or we might deadlock.
  else if (config->mode != LSN_SIMPLE_SERVER) {
    log_debug(this, "client arming flush timer%s%s",
              sent_fin ? " (sent FIN)" : "",
              received_fin ? " (received FIN)": "");
    uint32_t next_try_interval = flush_interval();
    log_debug(this, "next try to connect to server in %u msecs", next_try_interval);
    arm_flush_timer(next_try_interval);
  }

  return 0;
}

int
chop_circuit_t::retransmit()
{
  //bool did_retransmit = false;
  // Consider retransmission.
  evbuffer *block = 0;
  for (transmit_queue::iterator i = tx_queue.begin();
       i != tx_queue.end();
       ++i) {
    transmit_elt &el = *i;
    size_t lo = MIN_BLOCK_SIZE + el.hdr.dlen(); //we don't need to add the min block size as it is done in pick_connections, maybe we sends these with double headers
    size_t room;
    chop_conn_t *conn = pick_connection(lo, lo, &room);
    if (!conn)
      continue;
    log_assert(lo <= room);
    
    if (!block)
      block = evbuffer_new();
    if (!block)
      log_abort("memory allocation failed");
    if (tx_queue.retransmit(el, room - lo, block,
                            *send_hdr_crypt, *send_crypt) ||
        conn->send(block)) {
      evbuffer_free(block);
      return -1;
    }
    
    char fallbackbuf[4];
    log_debug(conn, "retransmitted block %u <d=%lu p=%lu f=%s>",
              el.hdr.seqno(),
              (unsigned long)el.hdr.dlen(),
              (unsigned long)el.hdr.plen(),
              opname(el.hdr.opcode(), fallbackbuf));
    
    if (config->trace_packets)
      fprintf(stderr,
              "T:%.4f: ckt %u <ntp %u outq %lu>: "
              "resend %lu <d=%lu p=%lu f=%s>\n",
              log_get_timestamp(), this->serial,
              this->recv_queue.window(),
              (unsigned long)evbuffer_get_length(
                                                 bufferevent_get_input(this->up_buffer)),
              (unsigned long)el.hdr.seqno(),
              (unsigned long)el.hdr.dlen(),
              (unsigned long)el.hdr.plen(),
              opname(el.hdr.opcode(), fallbackbuf));

    evbuffer_free(block);
    //did_retransmit = true;
    break;
  }
  
  return 0;
}
// Connection methods

conn_t *
chop_config_t::conn_create(size_t index)
{
  chop_conn_t *conn = new chop_conn_t;
  conn->config = this;
  conn->steg = steg_targets.at(index)->steg_create(conn);

  if (!conn->steg) {
    free(conn);
    return 0;
  }

  conn->steg->cfg()->noise2signal = noise2signal;

  conn->recv_pending = evbuffer_new();
  return conn;
}

} // namespace

using namespace chop_protocol;

PROTO_DEFINE_MODULE(chop);


// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
