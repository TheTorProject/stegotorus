/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"

#include "container.h"
#include "main.h"
#include "network.h"
#include "protocol.h"
#include "socks.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

/** All active connections.  */
static smartlist_t *connections;

/** All active circuits.  */
static smartlist_t *circuits;

/** True when obfsproxy is shutting down: no further connections or
    circuits may be created, and we break out of the event loop when
    the last one (of either) is closed. */
static int shutting_down;

void
conn_initialize()
{
  connections = smartlist_create();
  circuits = smartlist_create();
}

static void
maybe_finish_shutdown(int barbaric)
{
  if (!shutting_down) return;

  if (barbaric ||
      (smartlist_len(circuits) == 0 && smartlist_len(connections) == 0)) {
    smartlist_free(circuits);
    smartlist_free(connections);
    finish_shutdown();
  }
}

void
conn_start_shutdown(int barbaric)
{
  shutting_down = 1;

  if (barbaric && smartlist_len(circuits) > 0) {
    SMARTLIST_FOREACH(circuits, circuit_t *, ckt, circuit_close(ckt));
  }
  if (barbaric && smartlist_len(connections) > 0) {
    SMARTLIST_FOREACH(connections, conn_t *, conn, conn_close(conn));
  }

  maybe_finish_shutdown(barbaric);
}

unsigned long
conn_count(void)
{
  return smartlist_len(connections);
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
    /* This will recurse into here after breaking circular references. */
    circuit_downstream_shutdown(conn->circuit, conn,
                                BEV_EVENT_READING|BEV_EVENT_WRITING);
    return;
  }

  smartlist_remove(connections, conn);
  log_debug("Closing connection with %s; %d remaining",
            conn->peername, smartlist_len(connections));

  if (conn->peername)
    free((void *)conn->peername);
  if (conn->buffer)
    bufferevent_free(conn->buffer);

  conn->cfg->vtable->conn_free(conn);

  maybe_finish_shutdown(0);
}

/* Protocol methods of connections. */

int
conn_handshake(conn_t *conn)
{
  return conn->cfg->vtable->handshake(conn);
}

int
conn_send(conn_t *dest, struct evbuffer *source)
{
  return dest->cfg->vtable->send(dest, source);
}

enum recv_ret
conn_recv(conn_t *source, struct evbuffer *dest)
{
  return source->cfg->vtable->recv(source, dest);
}

void
conn_expect_close(conn_t *conn)
{
  obfs_assert(conn->cfg->vtable->expect_close);
  conn->cfg->vtable->expect_close(conn);
}

void
conn_cease_transmission(conn_t *conn)
{
  obfs_assert(conn->cfg->vtable->cease_transmission);
  conn->cfg->vtable->cease_transmission(conn);
}

void
conn_close_after_transmit(conn_t *conn)
{
  obfs_assert(conn->cfg->vtable->close_after_transmit);
  conn->cfg->vtable->close_after_transmit(conn);
}

void
conn_transmit_soon(conn_t *conn, unsigned long timeout)
{
  obfs_assert(conn->cfg->vtable->transmit_soon);
  conn->cfg->vtable->transmit_soon(conn, timeout);
}

/* Circuits. */

circuit_t *
circuit_create(config_t *cfg, struct bufferevent *up, const char *peer)
{
  circuit_t *ckt;

  obfs_assert(!shutting_down);

  ckt = cfg->vtable->circuit_create(cfg);
  ckt->up_buffer = up;
  ckt->up_peer = peer;

  if (cfg->mode == LSN_SOCKS_CLIENT)
    ckt->socks_state = socks_state_new();

  smartlist_add(circuits, ckt);
  return ckt;
}

circuit_t *
circuit_create_with_downstream(config_t *cfg, conn_t *down)
{
  circuit_t *ckt;
  struct evutil_addrinfo *addr;
  struct event_base *base;
  struct bufferevent *buf;

  obfs_assert(!shutting_down);

  addr = config_get_target_addr(cfg);
  base = bufferevent_get_base(down->buffer);

  if (!addr) {
    log_warn("%s: no target addresses available", down->peername);
    return NULL;
  }

  buf = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: unable to create outbound socket buffer", down->peername);
    return NULL;
  }

  ckt = cfg->vtable->circuit_create(cfg);

  if (!circuit_connect_to_upstream(ckt, buf, addr)) {
    ckt->cfg->vtable->circuit_free(ckt);
    bufferevent_free(buf);
    return NULL;
  }

  ckt->downstream = down;
  down->circuit = ckt;
  smartlist_add(circuits, ckt);
  return ckt;
}

int
circuit_open_downstream_from_cfg(circuit_t *ckt)
{
  conn_t *down;
  struct evutil_addrinfo *addr;
  struct event_base *base;
  struct bufferevent *buf;

  obfs_assert(!shutting_down);

  addr = config_get_target_addr(ckt->cfg);
  base = bufferevent_get_base(ckt->up_buffer);

  if (!addr) {
    log_warn("%s: no target addresses available", ckt->up_peer);
    return 0;
  }

  buf = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: unable to create outbound socket buffer", ckt->up_peer);
    return 0;
  }

  down = conn_create_outbound(ckt->cfg, buf, addr);
  if (!down) {
    bufferevent_free(buf);
    return 0;
  }

  ckt->downstream = down;
  down->circuit = ckt;
  return 1;
}

int
circuit_open_downstream_from_socks(circuit_t *ckt)
{
  conn_t *down;
  struct event_base *base;
  struct bufferevent *buf;
  const char *hostname;
  int af, port;

  obfs_assert(!shutting_down);
  base = bufferevent_get_base(ckt->up_buffer);

  if (socks_state_get_address(ckt->socks_state, &af, &hostname, &port))
    log_error("%s: called from wrong socks state", __func__);

  buf = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: unable to create outbound socket buffer", ckt->up_peer);
    return 0;
  }

  down = conn_create_outbound_socks(ckt->cfg, buf, af, hostname, port);
  if (!down) {
    bufferevent_free(buf);
    return 0;
  }

  ckt->downstream = down;
  down->circuit = ckt;
  return 1;
}


void
circuit_close(circuit_t *ckt)
{
  /* break the circular reference before deallocating the
     downstream connection */
  if (ckt->downstream) {
    ckt->downstream->circuit = NULL;
    conn_close(ckt->downstream);
  }

  smartlist_remove(circuits, ckt);
  log_debug("Closing circuit with %s; %d remaining",
            ckt->up_peer, smartlist_len(circuits));

  if (ckt->up_buffer)
    bufferevent_free(ckt->up_buffer);
  if (ckt->up_peer)
    free((void *)ckt->up_peer);
  if (ckt->socks_state)
    socks_state_free(ckt->socks_state);

  ckt->cfg->vtable->circuit_free(ckt);

  maybe_finish_shutdown(0);
}

void
circuit_upstream_shutdown(circuit_t *ckt, unsigned short direction)
{
  obfs_assert(direction != 0);
  obfs_assert((direction & ~(BEV_EVENT_READING|BEV_EVENT_WRITING)) == 0);

  if (direction & BEV_EVENT_READING) {
    if (ckt->downstream) {
      conn_send(ckt->downstream, bufferevent_get_input(ckt->up_buffer));
      obfs_assert(!evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)));

      if (evbuffer_get_length(conn_get_outbound(ckt->downstream)))
        conn_do_flush(ckt->downstream);
      else {
        bufferevent_disable(ckt->downstream->buffer, EV_WRITE);
        shutdown(bufferevent_getfd(ckt->downstream->buffer), SHUT_WR);
      }
    } else
      evbuffer_drain(bufferevent_get_input(ckt->up_buffer),
                     evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)));

    bufferevent_disable(ckt->up_buffer, EV_READ);
    shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_RD);
  }

  if (direction & BEV_EVENT_WRITING) {
    bufferevent_disable(ckt->up_buffer, EV_WRITE);
    shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_WR);

    evbuffer_drain(bufferevent_get_output(ckt->up_buffer),
                   evbuffer_get_length(bufferevent_get_output(ckt->up_buffer)));

    if (ckt->downstream) {
      bufferevent_disable(ckt->downstream->buffer, EV_READ);
      shutdown(bufferevent_getfd(ckt->downstream->buffer), SHUT_RD);
      evbuffer_drain(conn_get_inbound(ckt->downstream),
                     evbuffer_get_length(conn_get_inbound(ckt->downstream)));
    }
  }

  /* If there is nothing left, we can close this circuit.  Do not
     close the downstream connection if it has anything left to write.  */
  if (!bufferevent_get_enabled(ckt->up_buffer)) {
    conn_t *conn = ckt->downstream;
    ckt->downstream = NULL;
    conn->circuit = NULL;
    circuit_close(ckt);
    if (evbuffer_get_length(conn_get_outbound(conn)) == 0)
      conn_close(conn);
  }
}

void
circuit_downstream_shutdown(circuit_t *ckt, conn_t *conn,
                            unsigned short direction)
{
  obfs_assert(direction != 0);
  obfs_assert((direction & ~(BEV_EVENT_READING|BEV_EVENT_WRITING)) == 0);
  obfs_assert(conn == ckt->downstream);
  obfs_assert(ckt == conn->circuit);

  if (direction & BEV_EVENT_READING) {
    if (ckt->up_buffer) {
      conn_recv(conn, bufferevent_get_output(ckt->up_buffer));
      obfs_assert(!evbuffer_get_length(conn_get_inbound(conn)));

      if (evbuffer_get_length(bufferevent_get_output(ckt->up_buffer)))
        circuit_do_flush(ckt);
      else {
        bufferevent_disable(ckt->up_buffer, EV_WRITE);
        shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_WR);
      }
    } else
      evbuffer_drain(conn_get_inbound(conn),
                     evbuffer_get_length(conn_get_inbound(conn)));

    bufferevent_disable(conn->buffer, EV_READ);
    shutdown(bufferevent_getfd(conn->buffer), SHUT_RD);
  }

  if (direction & BEV_EVENT_WRITING) {
    bufferevent_disable(conn->buffer, EV_WRITE);
    shutdown(bufferevent_getfd(conn->buffer), SHUT_WR);

    evbuffer_drain(conn_get_outbound(conn),
                   evbuffer_get_length(conn_get_outbound(conn)));

    if (ckt->up_buffer) {
      bufferevent_disable(ckt->up_buffer, EV_READ);
      shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_RD);
      evbuffer_drain(bufferevent_get_input(ckt->up_buffer),
                     evbuffer_get_length(bufferevent_get_input(ckt->up_buffer)));
    }
  }

  /* If there is nothing left, we can close this connection.  Do not
     close the circuit if its upstream buffer has anything left to write. */
  if (!bufferevent_get_enabled(conn->buffer)) {
    ckt->downstream = NULL;
    conn->circuit = NULL;
    conn_close(conn);
    if (evbuffer_get_length(bufferevent_get_output(ckt->up_buffer)) == 0)
      circuit_close(ckt);
  }
}
