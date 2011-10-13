/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "container.h"
#include "main.h"
#include "protocol.h"
#include "socks.h"

#include <event2/event.h>
#include <event2/buffer.h>

/** All active connections.  */
static smartlist_t *connections;

/** All active circuits.  */
static smartlist_t *circuits;

/** True when obfsproxy is shutting down: no further connections or
    circuits may be created, and we break out of the event loop when
    the last one (of either) is closed. */
static int shutting_down;

void
conn_initialize(void)
{
  connections = smartlist_create();
  circuits = smartlist_create();
}

static void
maybe_finish_shutdown(void)
{
  if (!shutting_down)
    return;
  if ((circuits && smartlist_len(circuits) > 0) ||
      (connections && smartlist_len(connections) > 0))
    return;

  if (circuits)
    smartlist_free(circuits);
  if (connections)
    smartlist_free(connections);
  finish_shutdown();
}

void
conn_start_shutdown(int barbaric)
{
  /* Do not set 'shutting_down' until after we take care of barbaric
     connection breakage, so that the calls below to circuit_close or
     conn_close do not cause maybe_finish_shutdown to take one of the
     lists out from under us. */
  shutting_down = 0;

  if (barbaric && circuits && smartlist_len(circuits) > 0) {
    SMARTLIST_FOREACH(circuits, circuit_t *, ckt, circuit_close(ckt));
  }
  if (barbaric && connections && smartlist_len(connections) > 0) {
    SMARTLIST_FOREACH(connections, conn_t *, conn, conn_close(conn));
  }

  shutting_down = 1;
  maybe_finish_shutdown();
}

unsigned long
conn_count(void)
{
  return smartlist_len(connections);
}

unsigned long
circuit_count(void)
{
  return smartlist_len(circuits);
}

/**
   Creates a new conn_t from a config_t and a socket.
*/
conn_t *
conn_create(config_t *cfg, struct bufferevent *buf, const char *peername)
{
  conn_t *conn;

  obfs_assert(!shutting_down);

  conn = cfg->vtable->conn_create(cfg);
  conn->buffer = buf;
  conn->peername = peername;
  smartlist_add(connections, conn);
  return conn;
}

/**
   Deallocates conn_t 'conn'.
*/
void
conn_close(conn_t *conn)
{
  if (conn->circuit) {
    circuit_drop_downstream(conn->circuit, conn);
  }

  smartlist_remove(connections, conn);
  log_debug("Closing connection with %s; %d remaining",
            conn->peername, smartlist_len(connections));

  if (conn->peername)
    free((void *)conn->peername);
  if (conn->buffer)
    bufferevent_free(conn->buffer);

  conn->cfg->vtable->conn_free(conn);

  maybe_finish_shutdown();
}

/* Drain the transmit queue and send a TCP-level EOF indication to DEST. */
void
conn_send_eof(conn_t *dest)
{
  struct evbuffer *outbuf = conn_get_outbound(dest);
  if (evbuffer_get_length(outbuf)) {
    log_debug("%s: flushing out %ld bytes", dest->peername,
              (unsigned long) evbuffer_get_length(outbuf));
    conn_do_flush(dest);
  } else {
    log_debug("%s: sending EOF", dest->peername);
    bufferevent_disable(dest->buffer, EV_WRITE);
    shutdown(bufferevent_getfd(dest->buffer), SHUT_WR);
  }
}

/* Protocol methods of connections. */

int
conn_maybe_open_upstream(conn_t *conn)
{
  return conn->cfg->vtable->conn_maybe_open_upstream(conn);
}

int
conn_handshake(conn_t *conn)
{
  return conn->cfg->vtable->conn_handshake(conn);
}

int
conn_recv(conn_t *source)
{
  return source->cfg->vtable->conn_recv(source);
}

int
conn_recv_eof(conn_t *source)
{
  return source->cfg->vtable->conn_recv_eof(source);
}

void
conn_expect_close(conn_t *conn)
{
  conn->cfg->vtable->conn_expect_close(conn);
}

void
conn_cease_transmission(conn_t *conn)
{
  conn->cfg->vtable->conn_cease_transmission(conn);
}

void
conn_close_after_transmit(conn_t *conn)
{
  conn->cfg->vtable->conn_close_after_transmit(conn);
}

void
conn_transmit_soon(conn_t *conn, unsigned long timeout)
{
  conn->cfg->vtable->conn_transmit_soon(conn, timeout);
}

/* Circuits. */

/* The flush timer is used to ensure forward progress for protocols
   that can only send data in small chunks. */

static void
flush_timer_cb(evutil_socket_t fd, short what, void *arg)
{
  circuit_t *ckt = arg;
  log_debug("%s: flush timer expired, %ld bytes available", ckt->up_peer,
            (unsigned long)
            evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)));
  circuit_send(ckt);
}

/* The axe timer is used to clean up dead circuits for protocols where
   a circuit can legitimately exist for a little while with no
   connections. */

static void
axe_timer_cb(evutil_socket_t fd, short what, void *arg)
{
  circuit_t *ckt = arg;
  log_warn("%s: timeout, closing circuit", ckt->up_peer);
  circuit_close(ckt);
}

circuit_t *
circuit_create(config_t *cfg)
{
  circuit_t *ckt;

  obfs_assert(!shutting_down);

  ckt = cfg->vtable->circuit_create(cfg);

  if (cfg->mode == LSN_SOCKS_CLIENT)
    ckt->socks_state = socks_state_new();

  smartlist_add(circuits, ckt);
  return ckt;
}

void
circuit_add_upstream(circuit_t *ckt, struct bufferevent *buf, const char *peer)
{
  obfs_assert(!ckt->up_buffer);
  obfs_assert(!ckt->up_peer);

  ckt->up_buffer = buf;
  ckt->up_peer = peer;
}

/* circuit_open_upstream is in network.c */

void
circuit_add_downstream(circuit_t *ckt, conn_t *down)
{
  obfs_assert(!down->circuit);
  down->circuit = ckt;
  ckt->cfg->vtable->circuit_add_downstream(ckt, down);
}

void
circuit_drop_downstream(circuit_t *ckt, conn_t *down)
{
  obfs_assert(down->circuit == ckt);
  down->circuit = NULL;
  ckt->cfg->vtable->circuit_drop_downstream(ckt, down);
}

void
circuit_close(circuit_t *ckt)
{
  smartlist_remove(circuits, ckt);
  log_debug("Closing circuit with %s; %d remaining",
            ckt->up_peer, smartlist_len(circuits));

  if (ckt->up_buffer)
    bufferevent_free(ckt->up_buffer);
  if (ckt->up_peer)
    free((void *)ckt->up_peer);
  if (ckt->socks_state)
    socks_state_free(ckt->socks_state);
  if (ckt->flush_timer)
    event_free(ckt->flush_timer);

  ckt->cfg->vtable->circuit_free(ckt);

  maybe_finish_shutdown();
}

static int
circuit_send_raw(circuit_t *ckt)
{
  return ckt->cfg->vtable->circuit_send(ckt);
}

void
circuit_send(circuit_t *ckt)
{
  if (circuit_send_raw(ckt)) {
    log_info("%s: error during transmit", ckt->up_peer);
    circuit_close(ckt);
  }
}

static int
circuit_send_eof_raw(circuit_t *ckt)
{
  return ckt->cfg->vtable->circuit_send_eof(ckt);
}

void
circuit_send_eof(circuit_t *ckt)
{
  if (ckt->socks_state) {
    circuit_close(ckt);
  } else if (circuit_send_eof_raw(ckt)) {
    log_info("%s: error during transmit", ckt->up_peer);
    circuit_close(ckt);
  }
}

void
circuit_recv_eof(circuit_t *ckt)
{
  if (ckt->up_buffer) {
    struct evbuffer *outbuf = bufferevent_get_output(ckt->up_buffer);
    size_t outlen = evbuffer_get_length(outbuf);
    if (outlen) {
      log_debug("%s: flushing %ld bytes to upstream",
                ckt->up_peer, (unsigned long)outlen);
      circuit_do_flush(ckt);
    } else {
      log_debug("%s: sending EOF to upstream", ckt->up_peer);
      bufferevent_disable(ckt->up_buffer, EV_WRITE);
      shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_WR);
    }
  }
}

void
circuit_arm_flush_timer(circuit_t *ckt, unsigned int milliseconds)
{
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = milliseconds * 1000;

  if (!ckt->flush_timer)
    ckt->flush_timer = evtimer_new(ckt->cfg->base, flush_timer_cb, ckt);

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
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = milliseconds * 1000;

  if (!ckt->axe_timer)
    ckt->axe_timer = evtimer_new(ckt->cfg->base, axe_timer_cb, ckt);

  evtimer_add(ckt->axe_timer, &tv);
}

void
circuit_disarm_axe_timer(circuit_t *ckt)
{
  if (ckt->axe_timer)
    evtimer_del(ckt->axe_timer);
}
