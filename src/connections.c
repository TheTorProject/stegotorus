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
    circuit_close(conn->circuit); /* will recurse and take care of us */
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

void
conn_flush_and_close(conn_t *conn)
{
  circuit_t *ckt;
  if (!conn->circuit) {
    conn_close(conn);
    return;
  }

  ckt = conn->circuit;
  if (!ckt->up_buffer || !ckt->is_open || ckt->is_flushing) {
    conn_close(conn);
    return;
  }

  /* prevent further events from the broken connection */
  if (conn->buffer) {
    bufferevent_free(conn->buffer);
    conn->buffer = NULL;
  }

  circuit_do_flush(ckt);
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
circuit_flush_and_close(circuit_t *ckt)
{
  if (!ckt->downstream || !ckt->is_open || ckt->is_flushing) {
    circuit_close(ckt);
    return;
  }

  /* prevent further events from the broken connection */
  if (ckt->up_buffer) {
    bufferevent_free(ckt->up_buffer);
    ckt->up_buffer = NULL;
  }

  conn_do_flush(ckt->downstream);
}
