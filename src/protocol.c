/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#include "protocol.h"
#include "protocols/obfs2.h"
#include "protocols/dummy.h"

#include <stdlib.h>
#include <string.h>


/**
    All supported protocols should be put in this array.
    It's used by main.c.
*/
const protocol_vtable *const supported_protocols[] =
{
  &dummy_vtable,
  &obfs2_vtable,
};
const size_t n_supported_protocols =
  sizeof(supported_protocols)/sizeof(supported_protocols[0]);

/**
   This function figures out which protocol we want to set up, and
   gives 'n_options', 'options' and 'params' to the appropriate
   protocol-specific initalization function.
   This function is called once for every listener through the runtime
   of obfsproxy.
*/
protocol_params_t *
proto_params_init(int n_options, const char *const *options)
{
  size_t i;
  for (i = 0; i < n_supported_protocols; i++)
    if (!strcmp(*options, supported_protocols[i]->name))
      /* Remove the first element of 'options' (which is always the
         protocol name) from the list passed to the init method. */
      return supported_protocols[i]->init(n_options - 1, options + 1);

  return NULL;
}

/**
   This function destroys 'params'.
   It's called everytime we free a listener.
*/
void
proto_params_free(protocol_params_t *params)
{
  obfs_assert(params);
  obfs_assert(params->vtable);
  obfs_assert(params->vtable->fini);

  if (params->target_addr) {
    evutil_freeaddrinfo(params->target_addr);
    params->target_addr = NULL;
  }
  if (params->listen_addr) {
    evutil_freeaddrinfo(params->listen_addr);
    params->listen_addr = NULL;
  }

  params->vtable->fini(params);
}

/**
   This function is called once per connection and creates a protocol
   object to be used during the session.

   Return a 'protocol_t' if successful, NULL otherwise.
*/
protocol_t *
proto_create(protocol_params_t *params)
{
  obfs_assert(params);
  obfs_assert(params->vtable);
  obfs_assert(params->vtable->create);
  return params->vtable->create(params);
}

/**
   This function does the protocol handshake.
   Not all protocols have a handshake.
*/
int
proto_handshake(protocol_t *proto, void *buf) {
  obfs_assert(proto);
  obfs_assert(proto->vtable);
  obfs_assert(proto->vtable->handshake);
  return proto->vtable->handshake(proto, buf);
}

/**
   This function is responsible for sending protocol data.
*/
int
proto_send(protocol_t *proto, void *source, void *dest) {
  obfs_assert(proto);
  obfs_assert(proto->vtable);
  obfs_assert(proto->vtable->send);
  return proto->vtable->send(proto, source, dest);
}

/**
   This function is responsible for receiving protocol data.
*/
enum recv_ret
proto_recv(protocol_t *proto, void *source, void *dest) {
  obfs_assert(proto);
  obfs_assert(proto->vtable);
  obfs_assert(proto->vtable->recv);
  return proto->vtable->recv(proto, source, dest);
}

/**
   This function destroys 'proto'.
   It's called everytime we close a connection.
*/
void
proto_destroy(protocol_t *proto) {
  obfs_assert(proto);
  obfs_assert(proto->vtable);
  obfs_assert(proto->vtable->destroy);
  proto->vtable->destroy(proto);
}
