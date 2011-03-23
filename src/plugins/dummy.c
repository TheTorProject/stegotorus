/* Copyright 2011 Princess Peach Toadstool

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>

#include <openssl/rand.h>
#include <event2/buffer.h>

#include "dummy.h"
#include "../util.h"
#include "../protocol.h"

int
dummy_new(struct protocol_t *proto_struct) {
  proto_struct->destroy = (void *)NULL;
  proto_struct->init = (void *)dummy_init;
  proto_struct->handshake = (void *)NULL;
  proto_struct->send = (void *)dummy_send;
  proto_struct->recv = (void *)dummy_recv;

  return 0;
}

int *
dummy_init(int *initiator) {
  /* Dodging state check. */
  return initiator;
}

int
dummy_send(void *nothing,
           struct evbuffer *source, struct evbuffer *dest) {
  (void)nothing;

  /* ASN evbuffer_add_buffer() doesn't work for some reason. */
  while (1) {
    int n = evbuffer_remove_buffer(source, dest, 1024);
    if (n <= 0)
      return 0;
  }
}

int
dummy_recv(void *nothing,
           struct evbuffer *source, struct evbuffer *dest) {
  (void)nothing;
  while (1) {
    int n = evbuffer_remove_buffer(source, dest, 1024);
    if (n <= 0)
      return 0;
  }
}
