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
#include "../network.h"

static int dummy_send(void *nothing,
                                struct evbuffer *source, struct evbuffer *dest);
static enum recv_ret dummy_recv(void *nothing, struct evbuffer *source,
                                struct evbuffer *dest);

static protocol_vtable *vtable=NULL;

int
dummy_init(void) {
  vtable = calloc(1, sizeof(protocol_vtable));
  if (!vtable)
    return -1;

  vtable->destroy = NULL;
  vtable->create = dummy_new;
  vtable->handshake = NULL;
  vtable->send = dummy_send;
  vtable->recv = dummy_recv;

  return 1;
}

void *
dummy_new(struct protocol_t *proto_struct, 
          protocol_params_t *params)
{
  proto_struct->vtable = vtable;

  /* Dodging state check. 
     This is terrible I know.*/
  return (void *)666U;
}

static int
dummy_send(void *nothing,
           struct evbuffer *source, struct evbuffer *dest) {
  (void)nothing;

  return evbuffer_add_buffer(dest,source);
}

static enum recv_ret
dummy_recv(void *nothing,
           struct evbuffer *source, struct evbuffer *dest) {
  (void)nothing;
  
  if (evbuffer_add_buffer(dest,source)<0)
    return RECV_BAD;
  else
    return RECV_GOOD;
}
