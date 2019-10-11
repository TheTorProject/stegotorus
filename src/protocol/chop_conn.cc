
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/util.h>

#include "chop_handshaker.h"
#include "chop_conn.h"
#include "chop_config.h"
#include "chop_circuit.h"

namespace chop_protocol {
  
chop_conn_t::chop_conn_t()
  :upstream(NULL), must_send_timer(NULL), sent_handshake(false)
{
}

chop_conn_t::~chop_conn_t()
{
  if (this->must_send_timer)
    event_free(this->must_send_timer);
  if (steg)
    delete steg;
  evbuffer_free(recv_pending);
}

void
chop_conn_t::close()
{
  //delete the timer and tell upstream to drop me
  emancipate_from_upstream();
  
  conn_t::close();
}

/**
   In case the connection is handled to the transparent proxy
   then chop circuit/protocol should no longer influence the
   status of the connection
 */
void
chop_conn_t::emancipate_from_upstream()
{
  if (this->must_send_timer) {
    event_del(this->must_send_timer);
    must_send_timer = NULL;
  }

  if (upstream)
    upstream->drop_downstream(this);

}

circuit_t *
chop_conn_t::circuit() const
{
  return upstream;
}

int
chop_conn_t::maybe_open_upstream()
{
  // We can't open the upstream until we have a circuit ID.
  return 0;
}

int
chop_conn_t::send(struct evbuffer *block)
{
  if (!sent_handshake && config->mode != LSN_SIMPLE_SERVER) {
    if (!upstream || upstream->circuit_id == 0)
      log_abort(this, "handshake: can't happen: up%c cid=%u",
                upstream ? '+' : '-',
                upstream ? upstream->circuit_id : 0);
    /*hear we need to cook the handshake */
    uint8_t conn_handshake[HANDSHAKE_LEN];
    ChopHandshaker handshaker(upstream->circuit_id);
    handshaker.generate(conn_handshake, *(config->handshake_encryptor));
    
    if (evbuffer_prepend(block, (void *)conn_handshake,
                         HANDSHAKE_LEN)) {
      log_warn(this, "failed to prepend handshake to first block");
      return -1;
    }
  }

  int transmission_size = steg->transmit(block);
  if (transmission_size < 0) {
    log_warn(this, "failed to transmit block");
    return -1;
  }

  config->total_transmited_cover_bytes += transmission_size;
  sent_handshake = true;
  if (must_send_timer) {
    evtimer_del(must_send_timer);
    must_send_timer = NULL;
  }
  return 0;
}

int
chop_conn_t::handshake()
{
  // The actual handshake is generated in chop_conn_t::send so that it
  // can be merged with a block if possible; however, we use this hook
  // to ensure that the client sends _something_ ASAP after each new
  // connection, because the server can't forward traffic, or even
  // open a socket to its own upstream, until it knows which circuit
  // to associate this new connection with.  Note that in some cases
  // it's possible for us to have _already_ sent something on this
  // connection by the time we get called back!  Don't do it twice.
  if (config->mode != LSN_SIMPLE_SERVER && !sent_handshake)
    send();
  return 0;
}

/**
 checks if the handshake is correctly authenticated

 @return 0 success
         1 failed, transparentized the connection
        -1 failed, unrecoverable, please close the connection
*/
int
chop_conn_t::recv_handshake()
{
  log_assert(!upstream);
  log_assert(config->mode == LSN_SIMPLE_SERVER);

  uint32_t circuit_id;
  ChopHandshaker handshaker;
  uint8_t conn_handshake[HANDSHAKE_LEN];

  if (evbuffer_remove(recv_pending, (void *)conn_handshake,
                      HANDSHAKE_LEN) != (signed) HANDSHAKE_LEN)
    return -1;

  if (!handshaker.verify_and_extract(conn_handshake, *(config->handshake_decryptor))) {
    //invalid handshake, if we have a transparent proxy we 
    //we'll act as one for this connection
    log_warn("handshake authentication faild.");

    //so we need to axe the must send timer as the connection will be
    //managed by the transparent proxy and also drop the connection from
    //upstream circuit but not close it
    emancipate_from_upstream();
    
    if (config->transparent_proxy) {
      log_debug("stegotorus turning into a transparent proxy.");
      config->transparent_proxy->transparentize_connection(this, originally_received, received_length);
      return 1;
    }
    
    return -1;
  }

  circuit_id = handshaker.circuit_id;

  chop_circuit_table::value_type in(circuit_id, (chop_circuit_t *)0);
  std::pair<chop_circuit_table::iterator, bool> out
    = this->config->circuits.insert(in);
  chop_circuit_t *ck;

  if (!out.second) { // element already exists
    if (!out.first->second) {
      log_debug(this, "stale circuit");
      return 0;
    }
    ck = out.first->second;
    log_debug(this, "found circuit to %s", ck->up_peer);
  } else {
    ck = dynamic_cast<chop_circuit_t *>(circuit_create(this->config, 0));
    if (!ck) {
      log_warn(this, "failed to create new circuit");
      return -1;
    }
    if (ck->open_upstream()) {
      log_warn(this, "failed to begin upstream connection");
      ck->close();
      return -1;
    }
    log_debug(this, "created new circuit to %s", ck->up_peer);
    ck->circuit_id = circuit_id;
    out.first->second = ck;
  }

  ck->add_downstream(this);
  return 0;
}

int
chop_conn_t::recv()
{
  //TODO: This is too slow, we need to do it more cleverly.
  //we keep a copy of value of recv_pending, in case we need to
  //transparentize the connection
  if (config->mode == LSN_SIMPLE_SERVER && config->transparent_proxy) {
    received_length = evbuffer_get_length(bufferevent_get_input(buffer));
    originally_received = new uint8_t[received_length];
    log_assert(originally_received);
    if (evbuffer_copyout(bufferevent_get_input(buffer), originally_received, received_length) != (ssize_t) received_length)
      log_abort("was not able to make a copy of received data");
  }

  if (steg->receive(recv_pending)) {
    if ((config->mode == LSN_SIMPLE_SERVER ) && config->transparent_proxy) {
      //If steg fails in recovering the data
      //then maybe it wasn't an steg data to begin with
      //so we have transparent proxy we will become 
      //transparent at this moment
      log_debug("stegotorus turning into a transparent proxy.");
      config->transparent_proxy->transparentize_connection(this, originally_received, received_length);

      delete[] originally_received;
      return 0;
    }
    else
      return -1;
  }
  // If that succeeded but did not copy anything into recv_pending,
  // wait for more data.
  if (evbuffer_get_length(recv_pending) == 0)
    return 0;

  if (!upstream) {
    if (config->mode != LSN_SIMPLE_SERVER) {
      // We're the client.  Client connections start out attached to a
      // circuit; therefore this is a server-to-client message that
      // crossed with the teardown of the circuit it belonged to, and
      // we don't have the decryption keys for it anymore.
      // By construction it must be chaff, so just throw it away.
      log_debug(this, "discarding chaff after circuit closed");
      log_assert(!must_send_p());
      this->do_flush();
      return 0;
    }

    // We're the server. Try to receive a handshake.
    int handshake_result = recv_handshake();
    if (config->transparent_proxy) 
      delete [] originally_received; //done with this

    switch(handshake_result) 
      {
      case 1:
        //this connection was transparentized return 0 and don't 
        //worry about it any more
        return 0;
      case -1:
        //unrecoverable error, close the connection
        return -1;
      }

    // If we get here and ->upstream is not set, this is a connection
    // for a stale circuit: that is, a new connection made by the
    // client (to draw more data down from the server) that crossed
    // with a server-to-client FIN, the client-to-server FIN already
    // having been received and processed.  We no longer have the keys
    // to decrypt anything after the handshake, but it's either chaff
    // or a protocol error.  Either way, we can just drop the
    // connection, possibly sending a response if the cover protocol
    // requires one.
    if (!upstream) {
      if (must_send_p())
        send();
      this->do_flush();
      return 0;
    }
  }

  log_debug(this, "circuit to %s", upstream->up_peer);
  for (;;) {
    size_t avail = evbuffer_get_length(recv_pending);
    if (avail == 0)
      break;

    log_debug(this, "%lu bytes available", (unsigned long)avail);
    if (avail < MIN_BLOCK_SIZE) {
      log_debug(this, "incomplete block framing");
      break;
    }

    uint8_t ciphr_hdr[HEADER_LEN];
    if (evbuffer_copyout(recv_pending, ciphr_hdr, HEADER_LEN) !=
        (ssize_t)HEADER_LEN) {
      log_warn(this, "failed to copy out %lu bytes (header)",
               (unsigned long)HEADER_LEN);
      break;
    }

    header hdr(ciphr_hdr, *upstream->recv_hdr_crypt,
               upstream->recv_queue.window());
    if (!hdr.valid()) {
      uint8_t c[HEADER_LEN];
      upstream->recv_hdr_crypt->decrypt(c, ciphr_hdr);
      char fallbackbuf[4];
      log_info(this, "invalid block header: "
               "%02x%02x%02x%02x|%02x%02x|%02x%02x|%s|%02x|"
               "%02x%02x%02x%02x%02x%02x",
               c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
               opname(c[8], fallbackbuf),
               c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

      if (config->trace_packets)
        fprintf(stderr, "T:%.4f: ckt %u <ntp %u outq %lu>: recv-error "
                "%02x%02x%02x%02x <d=%02x%02x p=%02x%02x f=%s r=%02x "
                "c=%02x%02x%02x%02x%02x%02x>\n",
                log_get_timestamp(), upstream->serial,
                upstream->recv_queue.window(),
                (unsigned long)evbuffer_get_length(
                                  bufferevent_get_input(upstream->up_buffer)),
                c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
                opname(c[8], fallbackbuf),
                c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

      return -1;
    }
    if (avail < hdr.total_len()) {
      log_debug(this, "incomplete block (need %lu bytes)",
                (unsigned long)hdr.total_len());
      break;
    }

    uint8_t decodebuf[MAX_BLOCK_SIZE];
    if (evbuffer_drain(recv_pending, HEADER_LEN) ||
        evbuffer_remove(recv_pending, decodebuf, hdr.total_len() - HEADER_LEN)
        != (ssize_t)(hdr.total_len() - HEADER_LEN)) {
      log_warn(this, "failed to copy block to decode buffer");
      return -1;
    }
    if (upstream->recv_crypt->decrypt(decodebuf,
                                      decodebuf, hdr.total_len() - HEADER_LEN,
                                      ciphr_hdr, HEADER_LEN)) {
      log_warn("MAC verification failure");
      return -1;
    }

    char fallbackbuf[4];
    log_debug(this, "receiving block %u <d=%lu p=%lu f=%s r=%u>",
              hdr.seqno(), (unsigned long)hdr.dlen(), (unsigned long)hdr.plen(),
              opname(hdr.opcode(), fallbackbuf),
              hdr.rcount());

    if (config->trace_packets) {
      fprintf(stderr, "T:%.4f: ckt %u <ntp %u outq %lu>: recv %lu <d=%lu p=%lu f=%s r=%u>\n",
              log_get_timestamp(), upstream->serial,
              upstream->recv_queue.window(),
              (unsigned long)evbuffer_get_length(bufferevent_get_input(upstream->up_buffer)),
              (unsigned long)hdr.seqno(),
              (unsigned long)hdr.dlen(),
              (unsigned long)hdr.plen(),
              opname(hdr.opcode(), fallbackbuf),
              hdr.rcount());

         // vmon: I need the content of the packet as well.
        if (config->trace_packet_data && hdr.dlen())
          {
            char data_4_log[hdr.dlen() + 1];
            memcpy(data_4_log, decodebuf, hdr.dlen());
            data_4_log[hdr.dlen()] = '\0';
            log_debug("Data received: %s",  data_4_log);
            
          }
      }
    
    evbuffer *data = evbuffer_new();
    if (!data || (hdr.dlen() && evbuffer_add(data, decodebuf, hdr.dlen()))) {
      log_warn(this, "failed to extract data from decode buffer");
      evbuffer_free(data);
      return -1;
    }

    if (upstream->recv_block(hdr.seqno(), hdr.opcode(), data, this->steg->cfg())) {
      log_warn(this, "failed to insert the data in recv queue");
      return -1; // insert() logs an error
    }
  }

  return upstream->process_queue();
}

int
chop_conn_t::recv_eof()
{
  // Consume any not-yet-processed incoming data.  It's possible for
  // us to get here before we've processed _any_ data -- including the
  // handshake! -- from a new connection, so we have to do this before
  // we look at ->upstream.  */
  if (evbuffer_get_length(inbound()) > 0) {
    if (recv())
      return -1;
    // If there's anything left in the buffer at this point, it's a
    // protocol error.
    if (evbuffer_get_length(inbound()) > 0)
      return -1;
  }

  // We should only drop the connection from the circuit if we're no
  // longer sending covert data in the opposite direction _and_ the
  // cover protocol does not need us to send a reply (i.e. the
  // must_send_timer is not pending).
  if (upstream && (upstream->sent_fin || no_more_transmissions) &&
      !must_send_p() && evbuffer_get_length(outbound()) == 0)
    upstream->drop_downstream(this);

  return 0;
}

void
chop_conn_t::expect_close()
{
  read_eof = true;
}

void
chop_conn_t::cease_transmission()
{
  no_more_transmissions = true;
  if (must_send_timer) {
    evtimer_del(must_send_timer);
    must_send_timer = NULL;
  }
  
  this->do_flush();
}

void
chop_conn_t::transmit_soon(unsigned long milliseconds)
{
  struct timeval tv;

  log_debug(this, "must send within %lu milliseconds", milliseconds);

  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  if (!must_send_timer)
    must_send_timer = evtimer_new(config->base, must_send_timeout, this);
  evtimer_add(must_send_timer, &tv);
}

void
chop_conn_t::send()
{
  if (must_send_timer) {
    evtimer_del(must_send_timer);
    must_send_timer = NULL;
  }

  if (!steg) {
    log_warn(this, "send() called with no steg module available");
    this->do_flush();
    return;
  }

  if (write_eof) {
    log_warn(this, "send() called while connection buffer is shut down to write.");
    //this->do_flush();
    return;
  }

  // When this happens, we must send _even if_ we have no upstream to
  // provide us with data.  For instance, to preserve the cover
  // protocol, we must send an HTTP reply to each HTTP query that
  // comes in for a stale circuit.
  if (upstream) {
    log_debug(this, "must send");
    if (upstream->send_targeted(this)) {
      upstream->drop_downstream(this);
      this->do_flush();
    }

  } else {
    log_debug(this, "must send (no upstream)");

    size_t room = steg->transmit_room(MIN_BLOCK_SIZE, MIN_BLOCK_SIZE,
                                      MAX_BLOCK_SIZE);
    if (room < MIN_BLOCK_SIZE || room >= MAX_BLOCK_SIZE)
      log_abort(this, "steg size request (%lu) out of range [%lu, %lu]",
                (unsigned long)room,
                (unsigned long)MIN_BLOCK_SIZE,
                (unsigned long)MAX_BLOCK_SIZE);

    // Since we have no upstream, we can't encrypt anything; instead,
    // generate random bytes and feed them straight to steg_transmit.
    struct evbuffer *chaff = evbuffer_new();
    struct evbuffer_iovec v;
    if (!chaff || evbuffer_reserve_space(chaff, room, &v, 1) != 1 ||
        v.iov_len < room) {
      log_warn(this, "memory allocation failed");
      if (chaff)
        evbuffer_free(chaff);
      this->do_flush();
      return;
    }
    v.iov_len = room;
    rng_bytes((uint8_t *)v.iov_base, room);
    if (evbuffer_commit_space(chaff, &v, 1)) {
      log_warn(this, "evbuffer_commit_space failed");
      if (chaff)
        evbuffer_free(chaff);
      this->do_flush();
      return;
    }
    
    int transmission_size = steg->transmit(chaff);
    if (transmission_size < 0)
      this->do_flush();
    else
      config->total_transmited_cover_bytes += transmission_size;

    evbuffer_free(chaff);
  }
}

bool
chop_conn_t::must_send_p() const
{
  return must_send_timer && evtimer_pending(must_send_timer, 0);
}

/* static */ void
chop_conn_t::must_send_timeout(evutil_socket_t, short, void *arg)
{
  static_cast<chop_conn_t *>(arg)->send();
}

}
