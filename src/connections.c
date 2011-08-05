/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"

#include "container.h"
#include "main.h"
#include "protocol.h"
#include "socks.h"

#include <event2/bufferevent.h>

/** All active connections.  */
static smartlist_t *connections;

/** True when obfsproxy is shutting down: no further connections may
    be created, and we break out of the event loop when the last
    connection is closed. */

static int shutting_down;

/**
   Creates a new conn_t from a config_t and a socket.
*/
conn_t *
conn_create(config_t *cfg)
{
  conn_t *conn;

  obfs_assert(!shutting_down);

  if (!connections)
    connections = smartlist_create();
  conn = proto_conn_create(cfg);
  smartlist_add(connections, conn);
  return conn;
}

/**
   Deallocates conn_t 'conn'.
*/
void
conn_free(conn_t *conn)
{
  if (conn->circuit) {
    circuit_free(conn->circuit); /* will recurse and take care of us */
    return;
  }

  if (connections) {
    smartlist_remove(connections, conn);
    log_debug("Closing connection with %s; %d remaining",
              conn->peername, smartlist_len(connections));
    if (shutting_down && smartlist_len(connections) == 0) {
      smartlist_free(connections);
      finish_shutdown();
    }
  }

  if (conn->peername)
    free(conn->peername);
  if (conn->buffer)
    bufferevent_free(conn->buffer);
  proto_conn_free(conn);
}

void
conn_start_shutdown(int barbaric)
{
  if (!connections) {
    finish_shutdown();
  } else if (smartlist_len(connections) == 0) {
    smartlist_free(connections);
    finish_shutdown();
  } else if (barbaric) {
    SMARTLIST_FOREACH(connections, conn_t *, conn, conn_free(conn));
    smartlist_free(connections);
    finish_shutdown();
  } else {
    shutting_down = 1;
  }
}

unsigned long
conn_count(void)
{
  if (!connections) return 0;
  return smartlist_len(connections);
}

/* Protocol methods of connections. */

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

/* Circuits.  Circuits are not tracked, they are owned by their connections. */

int
circuit_create(conn_t *up, conn_t *down)
{
  if (!up || !down)
    return -1;

  circuit_t *r = xzalloc(sizeof(circuit_t));
  r->upstream = up;
  r->downstream = down;
  up->circuit = r;
  down->circuit = r;
  return 0;
}

void
circuit_create_socks(conn_t *up)
{
  obfs_assert(up);

  circuit_t *r = xzalloc(sizeof(circuit_t));
  r->upstream = up;
  r->socks_state = socks_state_new();
  up->circuit = r;
}

int
circuit_add_down(circuit_t *circuit, conn_t *down)
{
  if (!down)
    return -1;
  circuit->downstream = down;
  down->circuit = circuit;
  return 0;
}

void
circuit_free(circuit_t *circuit)
{
  /* break the circular references before deallocating each side */
  if (circuit->upstream) {
    circuit->upstream->circuit = NULL;
    conn_free(circuit->upstream);
  }
  if (circuit->downstream) {
    circuit->downstream->circuit = NULL;
    conn_free(circuit->downstream);
  }
  if (circuit->socks_state)
    socks_state_free(circuit->socks_state);
  free(circuit);
}
