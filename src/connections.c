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
maybe_finish_shutdown()
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

  maybe_finish_shutdown();
}

/* Protocol methods of connections. */

int
conn_handshake(conn_t *conn)
{
  return conn->cfg->vtable->conn_handshake(conn);
}

static int
conn_send_raw(conn_t *dest, struct evbuffer *source)
{
  return dest->cfg->vtable->conn_send(dest, source);
}

void
conn_send(conn_t *dest, struct evbuffer *source)
{
  obfs_assert(dest);
  if (conn_send_raw(dest, source)) {
    log_debug("%s: error during transmit.", dest->peername);
    conn_close(dest);
  } else {
    log_debug("%s: transmitted %lu bytes.", dest->peername,
              (unsigned long) evbuffer_get_length(conn_get_outbound(dest)));
  }
}

static enum recv_ret
conn_recv_raw(conn_t *source)
{
  return source->cfg->vtable->conn_recv(source);
}

void
conn_recv(conn_t *source)
{
  obfs_assert(source);
  if (conn_recv_raw(source) == RECV_BAD) {
    log_debug("%s: error during receive.", source->peername);
    conn_close(source);
  }
}

static int
conn_send_eof_raw(conn_t *dest)
{
  return dest->cfg->vtable->conn_send_eof(dest);
}

void
conn_send_eof(conn_t *dest, struct evbuffer *source)
{
  struct evbuffer *outbuf = conn_get_outbound(dest);
  if (evbuffer_get_length(source)) {
    log_debug("%s: %ld bytes of pending input",
              dest->peername, (unsigned long)evbuffer_get_length(source));
    if (conn_send_raw(dest, source))
      log_debug("%s: error during final transmit", dest->peername);
    if (evbuffer_get_length(source)) {
      log_debug("%s: discarding %ld bytes of pending input",
                dest->peername, (unsigned long)evbuffer_get_length(source));
      evbuffer_drain(source, evbuffer_get_length(source));
    }
  }
  if (conn_send_eof_raw(dest)) {
    log_debug("%s: error sending EOF indication", dest->peername);
    /* this might have failed because the downstream is waiting to
       receive data before it can send, so don't disable writes yet */
    conn_do_flush(dest);
  } else if (evbuffer_get_length(outbuf)) {
    log_debug("%s: flushing out %ld bytes", dest->peername,
              (unsigned long) evbuffer_get_length(outbuf));
    conn_do_flush(dest);
  } else {
    log_debug("%s: sending EOF", dest->peername);
    bufferevent_disable(dest->buffer, EV_WRITE);
    shutdown(bufferevent_getfd(dest->buffer), SHUT_WR);
  }
}

void
conn_squelch(conn_t *source)
{
  struct evbuffer *inbuf = conn_get_inbound(source);
  size_t inlen = evbuffer_get_length(inbuf);

  log_debug("%s: squelching further transmissions", source->peername);
  bufferevent_disable(source->buffer, EV_READ);
  shutdown(bufferevent_getfd(source->buffer), SHUT_RD);

  if (inlen) {
    log_debug("%s: discarding %ld bytes of pending input",
              source->peername, (unsigned long) inlen);
    evbuffer_drain(inbuf, inlen);
  }
}

enum recv_ret
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
  obfs_assert(!ckt->downstream);

  ckt->downstream = down;
  down->circuit = ckt;
}

int
circuit_open_downstream(circuit_t *ckt)
{
  conn_t *down = conn_create_outbound(ckt);
  if (!down)
    return 0;

  circuit_add_downstream(ckt, down);
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

  maybe_finish_shutdown();
}

void
circuit_send(circuit_t *ckt)
{
  ckt->cfg->vtable->circuit_send(ckt);
}

void
circuit_recv_eof(circuit_t *ckt, conn_t *conn)
{
  struct evbuffer *outbuf = bufferevent_get_output(ckt->up_buffer);
  struct evbuffer *inbuf = conn_get_inbound(conn);
  size_t inlen = evbuffer_get_length(inbuf);
  size_t outlen;
  enum recv_ret r;

  if (inlen) {
    log_debug("%s: %ld bytes of pending input",
              conn->peername, (unsigned long)inlen);

    r = conn_recv_raw(conn);
    if (r == RECV_BAD)
      log_debug("%s: error during final receive", conn->peername);

    inlen = evbuffer_get_length(inbuf);
    if (inlen) {
      log_debug("%s: discarding %ld bytes of pending input",
                conn->peername, (unsigned long)inlen);
      evbuffer_drain(inbuf, inlen);
    }
  }

  r = conn_recv_eof(conn);
  if (r == RECV_BAD)
    log_debug("%s: error receiving EOF", conn->peername);

  outlen = evbuffer_get_length(outbuf);
  if (outlen) {
    log_debug("%s: flushing %ld bytes", ckt->up_peer, outlen);
    circuit_do_flush(ckt);
  } else {
    log_debug("%s: sending EOF", ckt->up_peer);
    bufferevent_disable(ckt->up_buffer, EV_WRITE);
    shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_WR);
  }
}

void
circuit_squelch(circuit_t *ckt)
{
  if (ckt->up_buffer) {
    struct evbuffer *inbuf = bufferevent_get_input(ckt->up_buffer);
    size_t inlen = evbuffer_get_length(inbuf);

    log_debug("%s: squelching further transmissions", ckt->up_peer);
    bufferevent_disable(ckt->up_buffer, EV_READ);
    shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_RD);

    if (inlen) {
      log_debug("%s: discarding %ld bytes of pending input",
                ckt->up_peer, inlen);
      evbuffer_drain(inbuf, inlen);
    }
  }
}

void
circuit_upstream_shutdown(circuit_t *ckt, unsigned short direction)
{
  obfs_assert(direction != 0);
  obfs_assert((direction & ~(BEV_EVENT_READING|BEV_EVENT_WRITING)) == 0);

  if (direction & BEV_EVENT_READING) {
    struct evbuffer *inbuf = bufferevent_get_input(ckt->up_buffer);
    log_debug("%s: upstream read shutdown", ckt->up_peer);

    if (ckt->downstream) {
      conn_send_eof(ckt->downstream, inbuf);
    } else {
      if (evbuffer_get_length(inbuf)) {
        log_debug("%s: no downstream connection, discarding %ld bytes",
                  ckt->up_peer, evbuffer_get_length(inbuf));
        evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
      }
      /* If we don't have a downstream connection at this point,
         we will never have one. */
      bufferevent_disable(ckt->up_buffer, EV_WRITE);
    }

    bufferevent_disable(ckt->up_buffer, EV_READ);
    shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_RD);
  }

  if (direction & BEV_EVENT_WRITING) {
    struct evbuffer *outbuf = bufferevent_get_output(ckt->up_buffer);
    log_debug("%s: upstream write shutdown", ckt->up_peer);

    bufferevent_disable(ckt->up_buffer, EV_WRITE);
    shutdown(bufferevent_getfd(ckt->up_buffer), SHUT_WR);

    if (evbuffer_get_length(outbuf)) {
      log_debug("%s: discarding %ld bytes of pending output",
                ckt->up_peer, (unsigned long)evbuffer_get_length(outbuf));
      evbuffer_drain(outbuf, evbuffer_get_length(outbuf));
    }

    if (ckt->downstream)
      conn_squelch(ckt->downstream);
  }

  /* If there is nothing left, we can close this circuit.  Do not
     close the downstream connection if it has anything left to write.  */
  if (!bufferevent_get_enabled(ckt->up_buffer)) {
    conn_t *conn = ckt->downstream;
    ckt->downstream = NULL;

    if (conn) {
      conn->circuit = NULL;
      if (evbuffer_get_length(conn_get_outbound(conn)) == 0) {
        log_info("%s: closing downstream connection to %s",
                 ckt->up_peer, conn->peername);
        conn_close(conn);
      }
    }

    log_info("%s: closing circuit", ckt->up_peer);
    circuit_close(ckt);
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
    struct evbuffer *inbuf = conn_get_inbound(conn);
    log_debug("%s: downstream read shutdown", conn->peername);

    if (ckt->up_buffer) {
      circuit_recv_eof(ckt, conn);
    } else if (evbuffer_get_length(inbuf)) {
      log_debug("%s: no upstream connection, discarding %ld bytes",
                conn->peername, evbuffer_get_length(inbuf));
      evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
    }

    bufferevent_disable(conn->buffer, EV_READ);
    shutdown(bufferevent_getfd(conn->buffer), SHUT_RD);
  }

  if (direction & BEV_EVENT_WRITING) {
    struct evbuffer *outbuf = conn_get_outbound(conn);
    log_debug("%s: downstream write shutdown", conn->peername);

    bufferevent_disable(conn->buffer, EV_WRITE);
    shutdown(bufferevent_getfd(conn->buffer), SHUT_WR);

    if (evbuffer_get_length(outbuf)) {
      log_debug("%s: discarding %ld bytes of pending output",
                conn->peername, (unsigned long)evbuffer_get_length(outbuf));
      evbuffer_drain(outbuf, evbuffer_get_length(outbuf));
    }

    circuit_squelch(ckt);
  }

  /* If there is nothing left, we can close this connection.  Do not
     close the circuit if its upstream buffer has anything left to write. */
  if (!bufferevent_get_enabled(conn->buffer)) {
    ckt->downstream = NULL;
    conn->circuit = NULL;
    if (evbuffer_get_length(bufferevent_get_output(ckt->up_buffer)) == 0) {
      log_info("%s: closing circuit", ckt->up_peer);
      circuit_close(ckt);
    }

    log_info("%s: closing downstream connection to %s",
             ckt->up_peer, conn->peername);
    conn_close(conn);
  }
}
