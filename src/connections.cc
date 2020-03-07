/* Copyright 2012-2019 Tor Project Inc.
 * Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */


#include <unordered_set>

#include <event2/event.h>
#include <event2/buffer.h>

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "socks.h"

using std::unordered_set;

static void close_cleanup_cb(evutil_socket_t, short, void *);

namespace {
struct conn_global_state
{
  /** All active connections.  */
  unordered_set<conn_t *> connections;

  /** Connections which are to be deallocated after we return to the
      event loop. */
  unordered_set<conn_t *> closed_connections;

  /** All active circuits.  */
  unordered_set<circuit_t *> circuits;

  /** Circuits which are to be deallocated after we return to the
      event loop. */
  unordered_set<circuit_t *> closed_circuits;

  /** The one and only event base used by this program.
      Not owned by this object. */
  struct event_base *the_event_base;

  /** Low-priority event which fires when there are connections or
      circuits waiting to be deallocated, and all other pending events
      have been processed.  This ensures that we don't deallocate
      connections that have pending events. */
  struct event *close_cleanup;

  /** Most recently assigned serial numbers for connections and circuits.
      Note that serial number 0 is never used. These are only used for
      debugging messages, so we don't worry about them wrapping around. */
  unsigned int last_conn_serial;
  unsigned int last_ckt_serial;

  /** True when stegotorus is shutting down: no further connections or
      circuits may be created, and we break out of the event loop when
      the last one (of either) is closed. */
  bool shutting_down;

  conn_global_state(struct event_base *evbase);
  ~conn_global_state();
};

conn_global_state::conn_global_state(struct event_base *evbase)
  : the_event_base(evbase),
    close_cleanup(0),
    last_conn_serial(0), last_ckt_serial(0),
    shutting_down(false)
{
  close_cleanup = evtimer_new(evbase, close_cleanup_cb, this);
  log_assert(close_cleanup);
  if (event_priority_set(close_cleanup, 1))
    log_abort("failed to demote priority of close-cleanup event");
}

conn_global_state::~conn_global_state()
{
  log_assert(shutting_down);
  log_assert(connections.empty());
  log_assert(closed_connections.empty());
  log_assert(circuits.empty());
  log_assert(closed_circuits.empty());

  event_free(close_cleanup);
}

} // anonymous namespace

static void
close_cleanup_cb(evutil_socket_t, short, void *arg)
{
  conn_global_state *cgs = (conn_global_state *)arg;

  log_debug("cleaning up %lu circuits and %lu connections",
            (unsigned long)cgs->closed_circuits.size(),
            (unsigned long)cgs->closed_connections.size());

  if (!cgs->closed_circuits.empty()) {
    unordered_set<circuit_t *> v;
    v.swap(cgs->closed_circuits);
    for (unordered_set<circuit_t *>::iterator i = v.begin();
         i != v.end(); i++)
      delete *i;
  }
  if (!cgs->closed_connections.empty()) {
    unordered_set<conn_t *> v;
    v.swap(cgs->closed_connections);
    for (unordered_set<conn_t *>::iterator i = v.begin();
         i != v.end(); i++)
      delete *i;
  }

  if (!cgs->shutting_down ||
      !cgs->circuits.empty() ||
      !cgs->connections.empty())
    return;

  log_debug("finishing shutdown");
  event_base_loopexit(cgs->the_event_base, NULL);
  delete cgs;
  cgs = 0;
}

static conn_global_state *cgs = NULL;

void
conn_global_init(struct event_base *evbase)
{
  cgs = new conn_global_state(evbase);
  
}

void
conn_start_shutdown(int barbaric)
{
  cgs->shutting_down = true;

  if (barbaric) {
    if (!cgs->circuits.empty()) {
      unordered_set<circuit_t *> v;
      v.swap(cgs->circuits);
      for (unordered_set<circuit_t *>::iterator i = v.begin();
           i != v.end(); i++)
        (*i)->close();
    }
    if (!cgs->connections.empty()) {
      unordered_set<conn_t *> v;
      v.swap(cgs->connections); //this is for not earasing the current iterator
      for (unordered_set<conn_t *>::iterator i = v.begin();
           i != v.end(); i++) 
        (*i)->close();
    }
  }

  /* Make sure close_cleanup_cb is called at least once after this
     point; if there were no connections to tear down it might not
     otherwise happen.  */
  event_active(cgs->close_cleanup, 0, 0);
}

size_t
conn_count(void)
{
  return cgs->connections.size();
}

size_t
circuit_count(void)
{
  return cgs->circuits.size();
}

/**
   Creates a new conn_t from a config_t and a socket.
*/
conn_t *
conn_create(config_t *cfg, size_t index,
            struct bufferevent *buf, const char *peername)
{
  conn_t *conn;

  log_assert(!cgs->shutting_down);

  conn = cfg->conn_create(index);
  if (!conn)
    return nullptr;
  
  conn->buffer = buf;
  conn->peername = peername;
  conn->serial = ++cgs->last_conn_serial;

  //keeping track of connection consumption
  time(&conn->creation_time);

  cgs->connections.insert(conn);
  log_debug(conn, "new connection");
  return conn;
  
}

/**
   Deallocates conn_t 'conn'.
*/
conn_t::~conn_t()
{
  if (this->peername)
    free((void *)this->peername);
  if (this->buffer)
    bufferevent_free(this->buffer);
}

void
conn_t::close()
{
  log_debug(this, "closing connection; %lu remaining",
            (unsigned long) cgs->connections.size());
  if (this->buffer)
    bufferevent_disable(this->buffer, EV_READ|EV_WRITE);

  bool need_event =
    cgs->closed_connections.empty() && cgs->closed_circuits.empty();

  cgs->connections.erase(this);
  cgs->closed_connections.insert(this);

  if (need_event)
    event_active(cgs->close_cleanup, 0, 0);
}

/** Potentially called during connection construction or destruction. */
circuit_t *
conn_t::circuit() const
{
  return 0;
}

/* Drain the transmit queue and send a TCP-level EOF indication to DEST. */
void
conn_t::send_eof()
{
  this->pending_write_eof = true;
  struct evbuffer *outbuf = this->outbound();
  if (evbuffer_get_length(outbuf)) {
    log_debug(this, "flushing out %lu bytes",
              (unsigned long) evbuffer_get_length(outbuf));
    this->do_flush();
  } else if (!this->write_eof) {
    log_debug(this, "sending EOF downstream");
    shutdown(bufferevent_getfd(this->buffer), SHUT_WR);
    this->write_eof = true;
  }
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
  ckt->send();
}

/* The axe timer is used to clean up dead circuits for protocols where
   a circuit can legitimately exist for a little while with no
   connections. */

static void
axe_timer_cb(evutil_socket_t, short, void *arg)
{
  circuit_t *ckt = (circuit_t *)arg;
  log_warn(ckt, "timeout waiting for new connections");

  ckt->do_flush();
}

circuit_t *
circuit_create(config_t *cfg, size_t index)
{
  circuit_t *ckt;

  log_assert(!cgs->shutting_down);

  ckt = cfg->circuit_create(index);
  ckt->serial = ++cgs->last_ckt_serial;

  if (cfg->mode == LSN_SOCKS_CLIENT)
    ckt->socks_state = socks_state_new();

  cgs->circuits.insert(ckt);
  log_debug(ckt, "new circuit");
  return ckt;
}

circuit_t::~circuit_t()
{
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
}

void
circuit_t::close()
{
  log_debug(this, "closing circuit; %lu remaining",
            (unsigned long)cgs->circuits.size());

  if (this->up_buffer)
    bufferevent_disable(this->up_buffer, EV_READ|EV_WRITE);
  if (this->flush_timer)
    event_del(this->flush_timer);
  if (this->axe_timer)
    event_del(this->axe_timer);

  bool need_event =
    cgs->closed_connections.empty() && cgs->closed_circuits.empty();

  cgs->circuits.erase(this);
  cgs->closed_circuits.insert(this);

  if (need_event)
    event_active(cgs->close_cleanup, 0, 0);
}

config_t *
circuit_t::cfg() const
{
  return 0;
}

void
circuit_t::add_upstream(struct bufferevent *buf, const char *peer)
{
  log_assert(!this->up_buffer);
  log_assert(!this->up_peer);

  this->up_buffer = buf;
  this->up_peer = peer;
}

/* TODO: circuit_open_upstream is in network.c should come here then */

void
circuit_t::recv_eof()
{
  this->pending_write_eof = true;
  if (!this->up_buffer || !this->connected) {
    log_debug(this, "holding EOF till connection");
    return;
  }

  struct evbuffer *outbuf = bufferevent_get_output(this->up_buffer);
  size_t outlen = evbuffer_get_length(outbuf);
  if (outlen) {
    log_debug(this, "flushing %lu bytes to upstream", (unsigned long)outlen);
    this->do_flush();
    return;
  }

  //check if we haven't sent eof already
  if (!this->write_eof) {
    log_debug(this, "sending EOF to upstream");
    this->write_eof = true;
    shutdown(bufferevent_getfd(this->up_buffer), SHUT_WR);
  } else {
    log_debug(this, "upstream has already EOFed");
  }
  
}

void
circuit_t::arm_flush_timer(unsigned int milliseconds)
{
  log_debug(this, "flush within %u milliseconds", milliseconds);

  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  if (!this->flush_timer)
    this->flush_timer = evtimer_new(this->cfg()->base, flush_timer_cb, this);

  evtimer_add(this->flush_timer, &tv);
}

void
circuit_t::disarm_flush_timer()
{
  if (this->flush_timer)
    evtimer_del(this->flush_timer);
}

void
circuit_t::arm_axe_timer(unsigned int milliseconds)
{
  log_debug(this, "axe after %u milliseconds", milliseconds);

  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  if (!this->axe_timer)
    this->axe_timer = evtimer_new(this->cfg()->base, axe_timer_cb, this);

  evtimer_add(this->axe_timer, &tv);
}

void
circuit_t::disarm_axe_timer()
{
  if (this->axe_timer)
    evtimer_del(this->axe_timer);
}
