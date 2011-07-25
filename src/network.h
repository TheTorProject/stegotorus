/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef NETWORK_H
#define NETWORK_H

struct event_base;
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

listener_t *listener_new(struct event_base *base,
                         struct protocol_params_t *params);
void free_all_listeners(void);

void start_shutdown(int barbaric);

#ifdef NETWORK_PRIVATE

struct bufferevent;
struct socks_state_t;
struct protocol_t;

typedef struct conn_t {
  struct protocol_t *proto;
  struct socks_state_t *socks_state;
  struct bufferevent *input;
  struct bufferevent *output;
  unsigned int mode : 30;
  unsigned int flushing : 1;
  unsigned int is_open : 1;
} conn_t;

#endif

#endif
