/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef NETWORK_H
#define NETWORK_H

typedef struct listener_t *listener;

struct sockaddr;
struct event_base;

#define LSN_SIMPLE_CLIENT 1
#define LSN_SIMPLE_SERVER 2
#define LSN_SOCKS_CLIENT  3

typedef struct listener_t listener_t;

listener_t *listener_new(
                 struct event_base *base,
                 int mode,
                 const struct sockaddr *on_address, int on_address_len,
                 const struct sockaddr *target_address, int target_address_len,
                 const char *shared_secret, size_t shared_secret_len);
void listener_free(listener_t *listener);

#endif
