/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef NETWORK_H
#define NETWORK_H

/* returns 1 on success, 0 on failure */
int create_listener(struct event_base *base, int argc, const char *const *argv);
void free_all_listeners(void);

void start_shutdown(int barbaric);

/**
  This struct defines the state of a listener on a particular address.
  Each protocol may extend this structure with additional private data
  by embedding it as the first member of a larger structure (standard
  fake-inheritance-in-C technique).  The protocol's listener_create()
  method is responsible for filling in the |vtable|, |listen_addr|,
  |target_addr|, and |mode| fields of this structure, but should leave
  the |listener| and |listen_addr_str| fields alone.
 */
struct listener_t {
  const protocol_vtable  *vtable;
  struct evconnlistener  *listener;
  struct evutil_addrinfo *listen_addr;
  char                   *listen_addr_str;
  struct evutil_addrinfo *target_addr;
  enum listen_mode        mode;
};

/**
   This struct defines the state of a connection between "upstream"
   and "downstream" peers (it's really two connections at the socket
   level).  Again, each protocol may extend this structure with
   additional private data by embedding it as the first member of a
   larger structure.  The protocol's conn_create() method is responsible
   only for filling in the |vtable| field of this structure, plus any
   private data of course.
 */
struct conn_t {
  const protocol_vtable *vtable;
  char                  *peername;
  socks_state_t         *socks_state;
  struct bufferevent    *upstream;
  struct bufferevent    *downstream;
  enum listen_mode       mode     : 30;
  unsigned int           flushing : 1;
  unsigned int           is_open  : 1;
};

#endif
