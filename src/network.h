/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef NETWORK_H
#define NETWORK_H

/* returns 1 on success, 0 on failure */
int open_listeners(struct event_base *base, config_t *cfg);
void close_all_listeners(void);

void start_shutdown(int barbaric);

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
  socks_state_t      *socks_state;
  circuit_t          *circuit;
  struct bufferevent *buffer;
  enum listen_mode    mode     : 30;
  unsigned int        flushing : 1;
  unsigned int        is_open  : 1;
};

/**
   This struct defines a pair of established connections.  The "upstream"
   connection is to the higher-level client or server that we are proxying
   traffic for.  The "downstream" connection is to the remote peer.
 */

struct circuit_t {
  conn_t             *upstream;
  conn_t             *downstream;
};

#endif
