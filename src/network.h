/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef NETWORK_H
#define NETWORK_H

#include <stdlib.h>

typedef struct listener_t *listener;

struct sockaddr;
struct event_base;
struct socks_state_t;

#define LSN_SIMPLE_CLIENT 1
#define LSN_SIMPLE_SERVER 2
#define LSN_SOCKS_CLIENT  3

typedef struct listener_t listener_t;
struct addrinfo;

listener_t *listener_new(
                         struct event_base *base,
                         int mode, int protocol,
                         const struct sockaddr *on_address, int on_address_len,
                         const struct sockaddr *target_address, int target_address_len,
                         const char *shared_secret);
void listener_free(listener_t *listener);

#ifdef NETWORK_PRIVATE
typedef struct conn_t {
  struct socks_state_t *socks_state;
  struct protocol_t *proto; /* ASN Do we like this here? We probably don't.
                               But it's so convenient!! So convenient! */
  int mode;
  struct bufferevent *input;
  struct bufferevent *output;
  unsigned int flushing : 1;
  unsigned int is_open : 1;
} conn_t;
#endif

#endif
