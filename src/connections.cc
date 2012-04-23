/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "connections.h"
#include "main.h"
#include "protocol.h"
#include "socks.h"

#include <tr1/unordered_set>

#include <event2/event.h>
#include <event2/buffer.h>

using std::tr1::unordered_set;

/** All active connections.  */
static unordered_set<conn_t *> connections;

/** All active circuits.  */
static unordered_set<circuit_t *> circuits;

/** Most recently assigned serial numbers for connections and circuits.
    Note that serial number 0 is never used. These are only used for
    debugging messages, so we don't worry about them wrapping around. */
static unsigned int last_conn_serial = 0;
static unsigned int last_ckt_serial = 0;

/** True when stegotorus is shutting down: no further connections or
    circuits may be created, and we break out of the event loop when
    the last one (of either) is closed. */
static bool shutting_down;

/** True in the middle of a barbaric connection shutdown; prevents
    maybe_finish_shutdown from shutting down too early. */
static bool closing_all_connections;

static void
maybe_finish_shutdown(void)
{
  if (!shutting_down || closing_all_connections ||
      !circuits.empty() || !connections.empty())
    return;

  finish_shutdown();
}

void
conn_start_shutdown(int barbaric)
{
  shutting_down = true;

  if (barbaric) {
    closing_all_connections = true;

    if (!circuits.empty()) {
      unordered_set<circuit_t *> v;
      v.swap(circuits);
      for (unordered_set<circuit_t *>::iterator i = v.begin();
           i != v.end(); i++)
        delete *i;
    }
    if (!connections.empty()) {
      unordered_set<conn_t *> v;
      v.swap(connections);
      for (unordered_set<conn_t *>::iterator i = v.begin();
           i != v.end(); i++)
        delete *i;
    }
    closing_all_connections = false;
  }

  maybe_finish_shutdown();
}

size_t
conn_count(void)
{
  return connections.size();
}

size_t
circuit_count(void)
{
  return circuits.size();
}

/**
   Creates a new conn_t from a config_t and a socket.
*/
conn_t *
conn_create(config_t *cfg, size_t index,
            struct bufferevent *buf, const char *peername)
{
  conn_t *conn;

  log_assert(!shutting_down);

  conn = cfg->conn_create(index);
  conn->buffer = buf;
  conn->peername = peername;
  conn->serial = ++last_conn_serial;
  connections.insert(conn);
  log_debug(conn, "new connection");
  return conn;
}

/**
   Deallocates conn_t 'conn'.
*/
conn_t::~conn_t()
{
  connections.erase(this);
  log_debug(this, "closing connection; %lu remaining",
            (unsigned long) connections.size());

  if (this->peername)
    free((void *)this->peername);
  if (this->buffer)
    bufferevent_free(this->buffer);

  maybe_finish_shutdown();
}

/** Potentially called during connection construction or destruction. */
circuit_t *
conn_t::circuit() const
{
  return 0;
}

/* Drain the transmit queue and send a TCP-level EOF indication to DEST. */
void
conn_send_eof(conn_t *dest)
{
  struct evbuffer *outbuf = dest->outbound();
  if (evbuffer_get_length(outbuf)) {
    log_debug(dest, "flushing out %lu bytes",
              (unsigned long) evbuffer_get_length(outbuf));
    conn_do_flush(dest);
  } else if (bufferevent_get_enabled(dest->buffer) & EV_WRITE) {
    log_debug(dest, "sending EOF downstream");
    bufferevent_disable(dest->buffer, EV_WRITE);
    shutdown(bufferevent_getfd(dest->buffer), SHUT_WR);
  } /* otherwise, it's already been done */
}

/* Circuits. */

/* The flush timer is used to ensure forward progress for protocols
   that can only send data in small chunks. */

static void
flush_timer_cb(evutil_socket_t, short, void *arg)
{
  circuit_t *ckt = (circuit_t *)arg;
  log_debug(ckt, "flush timer expired, %lu bytes available",
            (unsigned long)
            evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)));
  circuit_send(ckt);
}

/* The axe timer is used to clean up dead circuits for protocols where
   a circuit can legitimately exist for a little while with no
   connections. */

static void
axe_timer_cb(evutil_socket_t, short, void *arg)
{
  circuit_t *ckt = (circuit_t *)arg;
  log_warn(ckt, "timeout waiting for new connections");

  if (ckt->connected &&
      evbuffer_get_length(bufferevent_get_output(ckt->up_buffer)) > 0)
    circuit_do_flush(ckt);
  else
    delete ckt;
}

circuit_t *
circuit_create(config_t *cfg, size_t index)
{
  circuit_t *ckt;

  log_assert(!shutting_down);

  ckt = cfg->circuit_create(index);
  ckt->serial = ++last_ckt_serial;

  if (cfg->mode == LSN_SOCKS_CLIENT)
    ckt->socks_state = socks_state_new();

  circuits.insert(ckt);
  log_debug(ckt, "new circuit");
  return ckt;
}

circuit_t::~circuit_t()
{
  circuits.erase(this);
  log_debug(this, "closing circuit; %lu remaining",
            (unsigned long)circuits.size());

  if (this->up_buffer)
    bufferevent_free(this->up_buffer);
  if (this->up_peer)
    free((void *)this->up_peer);
  if (this->socks_state)
    socks_state_free(this->socks_state);
  if (this->flush_timer)
    event_free(this->flush_timer);
  if (this->axe_timer)
    event_free(this->axe_timer);

  maybe_finish_shutdown();
}

config_t *
circuit_t::cfg() const
{
  return 0;
}

void
circuit_add_upstream(circuit_t *ckt, struct bufferevent *buf, const char *peer)
{
  log_assert(!ckt->up_buffer);
  log_assert(!ckt->up_peer);

  ckt->up_buffer = buf;
  ckt->up_peer = peer;
}

/* circuit_open_upstream is in network.c */

void
circuit_send(circuit_t *ckt)
{
  if (ckt->send()) {
    log_info(ckt, "error during transmit");
    delete ckt;
  }
}

void
circuit_send_eof(circuit_t *ckt)
{
  if (ckt->socks_state) {
    log_debug(ckt, "EOF during SOCKS phase");
    delete ckt;
  } else if (ckt->send_eof()) {
    log_info(ckt, "error during transmit");
    delete ckt;
  }
}

void
circuit_recv_eof(circuit_t *ckt)
{
  if (ckt->up_buffer) {
    struct evbuffer *outbuf = bufferevent_get_output(ckt->up_buffer);
    size_t outlen = evbuffer_get_length(outbuf);
    if (outlen) {
      log_debug(ckt, "flushing %lu bytes to upstream", (unsigned long)outlen);
      circuit_do_flush(ckt);
    } else if (ckt->connected) {
      log_debug(ckt, "sending EOF to upstream");
      bufferevent_disable(ckt->up_buffer, EV_WRITE);
      shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_WR);
    } else {
      log_debug(ckt, "holding EOF till connection");
      ckt->pending_eof = 1;
    }
  } else {
    log_debug(ckt, "no buffer, holding EOF till connection");
    ckt->pending_eof = 1;
  }
}

void
circuit_arm_flush_timer(circuit_t *ckt, unsigned int milliseconds)
{
  log_debug(ckt, "flush within %u milliseconds", milliseconds);

  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  if (!ckt->flush_timer)
    ckt->flush_timer = evtimer_new(ckt->cfg()->base, flush_timer_cb, ckt);

  evtimer_add(ckt->flush_timer, &tv);
}

void
circuit_disarm_flush_timer(circuit_t *ckt)
{
  if (ckt->flush_timer)
    evtimer_del(ckt->flush_timer);
}

void
circuit_arm_axe_timer(circuit_t *ckt, unsigned int milliseconds)
{
  log_debug(ckt, "axe after %u milliseconds", milliseconds);

  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  if (!ckt->axe_timer)
    ckt->axe_timer = evtimer_new(ckt->cfg()->base, axe_timer_cb, ckt);

  evtimer_add(ckt->axe_timer, &tv);
}

void
circuit_disarm_axe_timer(circuit_t *ckt)
{
  if (ckt->axe_timer)
    evtimer_del(ckt->axe_timer);
}
