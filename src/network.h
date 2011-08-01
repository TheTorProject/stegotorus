/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef NETWORK_H
#define NETWORK_H

/* returns 1 on success, 0 on failure */
int create_listener(struct event_base *base, int argc, const char *const *argv);
void free_all_listeners(void);

void start_shutdown(int barbaric);

#ifdef NETWORK_PRIVATE

typedef struct listener_t {
  char *address;
  protocol_params_t *proto_params;
  struct evconnlistener *listener;
} listener_t;

typedef struct conn_t {
  char *peername;
  protocol_t *proto;
  socks_state_t *socks_state;
  struct bufferevent *upstream;
  struct bufferevent *downstream;
  unsigned int mode : 30;
  unsigned int flushing : 1;
  unsigned int is_open : 1;
} conn_t;

#endif

#endif
