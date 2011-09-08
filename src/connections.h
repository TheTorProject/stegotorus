/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include <event2/bufferevent.h>

/**
   This struct defines the state of one downstream socket-level
   connection.  Each protocol may extend this structure with
   additional private data by embedding it as the first member of a
   larger structure.  The protocol's conn_create() method is
   responsible only for filling in the |cfg| and |mode| fields of this
   structure, plus any private data of course.

   Connections are associated with circuits (and thus with upstream
   socket-level connections) as quickly as possible.
 */
struct conn_t {
  config_t           *cfg;
  circuit_t          *circuit;
  const char         *peername;
  struct bufferevent *buffer;
};

/** Initialize connection and circuit tracking.  Must be called before
    any function that creates connections or circuits is called. */
void conn_initialize(void);

/** When all currently-open connections and circuits are closed, stop
    the main event loop and exit the program.  If 'barbaric' is true,
    forcibly close them all now, then stop the event loop.  It
    is a bug to call any function that creates connections or circuits
    after conn_start_shutdown has been called. */
void conn_start_shutdown(int barbaric);

/** Create a new connection from a configuration. */
conn_t *conn_create(config_t *cfg, struct bufferevent *buf,
                    const char *peername);

/** Close and deallocate a connection.  If the connection is part of a
    circuit, close the other side of that circuit as well. */
void conn_close(conn_t *conn);

/** Report the number of currently-open connections. */
unsigned long conn_count(void);

/** Retrieve the inbound evbuffer for a connection. */
static inline struct evbuffer *conn_get_inbound(conn_t *conn)
{ return conn->buffer ? bufferevent_get_input(conn->buffer) : NULL; }

/** Retrieve the outbound evbuffer for a connection. */
static inline struct evbuffer *conn_get_outbound(conn_t *conn)
{ return conn->buffer ? bufferevent_get_output(conn->buffer) : NULL; }

/** Transmit the protocol-specific handshake message (if any) for a
    connection. */
int conn_handshake(conn_t *conn);

/** Encode the data in SOURCE according to the appropriate wire protocol,
    and transmit it on DEST. */
void conn_send(conn_t *dest, struct evbuffer *source);

/** Receive data from SOURCE, decode it, and write it to upstream. */
void conn_recv(conn_t *source);

/** Flush out any internally buffered data, and transmit an
    in-band end-of-file indicator to DEST if necessary.  */
int conn_send_eof(conn_t *dest);

/** No more data will be received from the peer; flush any internally
    buffered data to DEST. */
enum recv_ret conn_recv_eof(conn_t *source);

/* The next several conn_t methods are used by steganography modules to
   provide hints about appropriate higher-level behavior.  */

/** The peer is expected to close CONN without any further
    transmissions. */
void conn_expect_close(conn_t *conn);

/** Do not transmit any more data on this connection after the outbound
    queue has drained.  However, the peer may still send data back. */
void conn_cease_transmission(conn_t *conn);

/** Close CONN after all pending data is transmitted. */
void conn_close_after_transmit(conn_t *conn);

/** We must transmit something on this connection within TIMEOUT
    milliseconds. */
void conn_transmit_soon(conn_t *conn, unsigned long timeout);

/**
   This struct defines a pair of established connections.

   The "upstream" connection (which does not have a conn_t) is to the
   higher-level client or server that we are proxying traffic for.
   The "downstream" connection (which does have a conn_t) to the
   remote peer.  Circuits always have an upstream connection, and
   normally also have a downstream connection; however, a circuit
   that's waiting for SOCKS directives from its upstream will have a
   non-null socks_state field instead.

   A circuit is "open" if both its upstream and downstream connections
   have been established (not just if all the objects exist).  It is
   "flushing" if one of the two connections has hit either EOF or an
   error, and we are clearing out the other side's pending
   transmissions before closing it.  Both of these flags are used
   near-exclusively for assertion checks; the actual behavior is
   controlled by changing bufferevent callbacks.

   Like conn_t, the protocol has an opportunity to add information to
   this structure.
 */

struct circuit_t {
  config_t           *cfg;
  struct bufferevent *up_buffer;
  const char         *up_peer;

  conn_t             *downstream;
  socks_state_t      *socks_state;
};

circuit_t *circuit_create_from_upstream(config_t *cfg, struct bufferevent *up,
                                        const char *peer);
circuit_t *circuit_create_from_downstream(config_t *cfg, conn_t *down);

int circuit_open_downstream(circuit_t *ckt);

void circuit_close(circuit_t *ckt);

void circuit_send(circuit_t *ckt);
void circuit_recv(circuit_t *ckt, conn_t *down);

void circuit_upstream_shutdown(circuit_t *ckt, unsigned short direction);
void circuit_downstream_shutdown(circuit_t *ckt, conn_t *conn,
                                 unsigned short direction);

unsigned long circuit_count(void);

#endif
