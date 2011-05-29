#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "protocol.h"
#include "network.h"

#include "protocols/obfs2.h"
#include "protocols/dummy.h"

/**
   This function initializes <protocol>. 
   It's called once in the runtime of the program for each proto.
*/
int
set_up_protocol(int n_options, char **options, 
                struct protocol_params_t *params)
{
  char **name = options;
  while (!strncmp(*name,"--",2))
         name++;
  if (!strcmp(*name,"dummy"))
    return dummy_init(n_options, options, params);
  else if (!strcmp(*name,"obfs2"))
    return obfs2_init(n_options, options, params);
  else
    return -1;
}

/**
   This function creates a protocol object. It's called once
   for every connection. It creates a new protocol_t structure
   and fills it's vtable etc.
   Return the protocol_t if successful, NULL otherwise.
*/
struct protocol_t *
proto_new(protocol_params_t *params) {
  struct protocol_t *proto = calloc(1, sizeof(struct protocol_t));
  if (!proto)
    return NULL;

  proto->vtable = calloc(1, sizeof(struct protocol_vtable));
  if (!proto->vtable)
    return NULL;

  if (params->proto == OBFS2_PROTOCOL) {
    proto->state = obfs2_new(proto, params);
  } else if (params->proto == DUMMY_PROTOCOL) {
    proto->state = dummy_new(proto, NULL);
  }

  if (proto->state)
    return proto;
  else
    return NULL;
}

int
proto_handshake(struct protocol_t *proto, void *buf) {
  assert(proto);
  if (proto->vtable->handshake)
    return proto->vtable->handshake(proto->state, buf);
  else /* It's okay with me, protocol didn't have a handshake */
    return 0;
}

int
proto_send(struct protocol_t *proto, void *source, void *dest) {
  assert(proto);
  if (proto->vtable->send)
    return proto->vtable->send(proto->state, source, dest);
  else 
    return -1;
}

int
proto_recv(struct protocol_t *proto, void *source, void *dest) {
  assert(proto);
  if (proto->vtable->recv)
    return proto->vtable->recv(proto->state, source, dest);
  else
    return -1;
}

void 
proto_destroy(struct protocol_t *proto) {
  assert(proto);
  assert(proto->state);

  if (proto->vtable->destroy)
    proto->vtable->destroy(proto->state);
}
