/* Copyright 2011 Princess Peach Toadstool

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef DUMMY_H
#define DUMMY_H

struct protocol_t;
struct evbuffer;

int *dummy_init(int *initiator);
int dummy_send(void *nothing,
               struct evbuffer *source, struct evbuffer *dest);
int dummy_recv(void *nothing, struct evbuffer *source,
               struct evbuffer *dest);
int dummy_new(struct protocol_t *proto_struct);

#endif
