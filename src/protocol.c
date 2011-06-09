#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "protocol.h"
#include "network.h"

#include "protocols/obfs2.h"
#include "protocols/dummy.h"

/** 
    All supported protocols should be put in this array.
    It's used by main.c.
*/
char *supported_protocols[] = { "obfs2", "dummy" };
int n_supported_protocols = 2;

/**
   This function figures out which protocol we want to set up, and
   gives 'n_options', 'options' and 'params' to the appropriate
   protocol-specific initalization function.
   This function is called once for every listener through the runtime
   of obfsproxy.
*/
int
set_up_protocol(int n_options, char **options, 
                struct protocol_params_t *params)
{
  if (!strcmp(*options,"dummy"))
    return dummy_init(n_options, options, params);
  else if (!strcmp(*options,"obfs2"))
    return obfs2_init(n_options, options, params);
  else
    return -1;
}

/**
   This function creates a protocol object.
   It's called once per connection. 
   It creates a new protocol_t structure and fills it's vtable etc.
   Return a 'protocol_t' if successful, NULL otherwise.
*/
struct protocol_t *
proto_new(protocol_params_t *params) {
  struct protocol_t *proto = calloc(1, sizeof(struct protocol_t));
  if (!proto)
    return NULL;

  if (params->proto == OBFS2_PROTOCOL)
    proto->state = obfs2_new(proto, params);
  else if (params->proto == DUMMY_PROTOCOL)
    proto->state = dummy_new(proto, NULL);

  return proto->state ? proto : NULL;
}

/**
   This function does the protocol handshake.
   Not all protocols have a handshake.
*/
int
proto_handshake(struct protocol_t *proto, void *buf) {
  assert(proto);
  if (proto->vtable->handshake)
    return proto->vtable->handshake(proto->state, buf);
  else /* It's okay with me, protocol didn't have a handshake */
    return 0;
}

/**
   This function is responsible for sending protocol data.
*/
int
proto_send(struct protocol_t *proto, void *source, void *dest) {
  assert(proto);
  if (proto->vtable->send)
    return proto->vtable->send(proto->state, source, dest);
  else 
    return -1;
}

/**
   This function is responsible for receiving protocol data.
*/
enum recv_ret
proto_recv(struct protocol_t *proto, void *source, void *dest) {
  assert(proto);
  if (proto->vtable->recv)
    return proto->vtable->recv(proto->state, source, dest);
  else
    return -1;
}

/**
   This function destroys 'proto'.
   It's called everytime we close a connection.
*/
void 
proto_destroy(struct protocol_t *proto) {
  assert(proto);
  assert(proto->state);

  if (proto->vtable->destroy)
    proto->vtable->destroy(proto->state);

  free(proto);
}

/**
   This function destroys 'params'.
   It's called everytime we free a listener.
*/
void
proto_params_free(protocol_params_t *params)
{
  assert(params);

  if (params->shared_secret)
    free(params->shared_secret);
  free(params);
}
