/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef NETWORK_H
#define NETWORK_H

#include <stdlib.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/event.h>


typedef struct listener_t *listener;

struct sockaddr;
struct event_base;
struct socks_state_t;
struct protocol_params_t;

#define LSN_SIMPLE_CLIENT 1
#define LSN_SIMPLE_SERVER 2
#define LSN_SOCKS_CLIENT  3

enum recv_ret {
  /* Everything went fine. */
  RECV_GOOD=0,
  /* Something went bad. */
  RECV_BAD,
  /* ...need...more...data... */
  RECV_INCOMPLETE,

  /* Originally needed by the obfs2 protocol but it might get other
     users in the future.
     It means:
     "We have pending data that we have to send. You should do that by
     calling proto_send() immediately." */
  RECV_SEND_PENDING
};

typedef struct listener_t listener_t;
struct addrinfo;

listener_t *listener_new(struct event_base *base,
                         struct protocol_params_t *params);
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
