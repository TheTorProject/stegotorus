/* Copyright 2011 Nick Mathewson, George Kadianakis, Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include <event2/bufferevent.h>

/**
   This struct defines the state of one socket-level connection.  Each
   protocol may extend this structure with additional private data by
   embedding it as the first member of a larger structure.  The
   protocol's conn_create() method is responsible only for filling in
   the |cfg| and |mode| fields of this structure, plus any private
   data of course.

   An incoming connection is not associated with a circuit until the
   destination for the other side of the circuit is known.  An outgoing
   connection is associated with a circuit from its creation.
 */
struct conn_t {
  config_t           *cfg;
  char               *peername;
  circuit_t          *circuit;
  struct bufferevent *buffer;
};

/** Create a new connection from a configuration. */
conn_t *conn_create(config_t *cfg);

/** Close and deallocate a connection.  If the connection is part of a
    circuit, close the other side of that circuit as well. */
void conn_free(conn_t *conn);

/** Report the number of currently-open connections. */
unsigned long conn_count(void);

/** When all currently-open connections are closed, stop the event
    loop and exit the program.  If 'barbaric' is true, forcibly close
    all connections now, then stop the event loop.  It is a bug to call
    conn_create after conn_start_shutdown has been called. */
void conn_start_shutdown(int barbaric);

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
int conn_send(conn_t *dest, struct evbuffer *source);

/** Receive data from SOURCE, decode it, and write it to DEST. */
enum recv_ret conn_recv(conn_t *source, struct evbuffer *dest);

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

   The "upstream" connection is to the higher-level client or server
   that we are proxying traffic for.  The "downstream" connection is
   to the remote peer.  Circuits always have an upstream connection,
   and normally also have a downstream connection; however, a circuit
   that's waiting for SOCKS directives from its upstream will have a
   non-null socks_state field instead.

   A circuit is "open" if both its upstream and downstream connections
   have been established (not just if both conn_t objects exist).
   It is "flushing" if one of the two connections has hit either EOF
   or an error, and we are clearing out the other side's pending
   transmissions before closing it.  Both of these flags are used
   near-exclusively for assertion checks; the actual behavior is
   controlled by changing bufferevent callbacks on the connections.
 */

struct circuit_t {
  conn_t             *upstream;
  conn_t             *downstream;
  socks_state_t      *socks_state;
  unsigned int        is_open : 1;
  unsigned int        is_flushing : 1;
};

int circuit_create(conn_t *up, conn_t *down);
void circuit_create_socks(conn_t *up);
int circuit_add_down(circuit_t *circuit, conn_t *down);
void circuit_free(circuit_t *circuit);

#endif
