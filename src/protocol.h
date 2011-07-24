/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "network.h"  /* for recv_ret */
#include <event2/util.h> /* for evutil_addrinfo */

struct evbuffer;

/**
  This struct defines the protocol-specific state for all connections
  opened from a particular listener.  Each protocol may extend this
  structure with additional private data by embedding it as the first
  member of a larger structure (standard fake-inheritance-in-C
  technique).
 */
typedef struct protocol_params_t {
  const struct protocol_vtable *vtable;
  struct evutil_addrinfo *target_addr;
  struct evutil_addrinfo *listen_addr;
  int mode;
} protocol_params_t;

/**
   This struct defines the protocol-specific state for a particular
   connection.  Again, each protocol may extend this structure with
   additional private data by embedding it as the first member of a
   larger structure.
 */
typedef struct protocol_t {
  const struct protocol_vtable *vtable;
} protocol_t;

/**
   This struct defines a protocol and its methods; note that not all
   of them are methods on the same object in the C++ sense.

   A filled-in, statically allocated protocol_vtable object is the
   principal interface between each individual protocol and generic
   code.  At present there is a static list of these objects in protocol.c.
 */
typedef struct protocol_vtable
{
  /** The short name of this protocol. */
  const char *name;

  /** Initialization: Allocate a 'protocol_params_t' object and fill
      it in from the provided 'options' array. */
  protocol_params_t *(*init)(int n_options, const char *const *options);

  /** Finalization: Destroy the provided 'protocol_params_t' object.
      This function is responsible for deallocating any data that the
      protocol's extended structure points to, and deallocating the
      object itself.  But it is *not* responsible for deallocating the
      data pointed to by the generic 'protocol_params_t'; that's
      already been done.  */
  void (*fini)(protocol_params_t *params);

  /** Constructor: Allocates per-connection, protocol-specific state. */
  protocol_t *(*create)(protocol_params_t *params);

  /** Destructor: Destroys per-connection, protocol-specific state.  */
  void (*destroy)(protocol_t *state);

  /** Perform a connection handshake. Not all protocols have a handshake. */
  int (*handshake)(protocol_t *state, struct evbuffer *buf);

  /** Send data coming downstream from 'source' along to 'dest'. */
  int (*send)(protocol_t *state,
              struct evbuffer *source,
              struct evbuffer *dest);

  /** Receive data from 'source' and pass it upstream to 'dest'. */
  enum recv_ret (*recv)(protocol_t *state,
                        struct evbuffer *source,
                        struct evbuffer *dest);

} protocol_vtable;

/**
   Use this macro to define protocol_vtable objects; it ensures all
   the methods are in the correct order and enforces a consistent
   naming convention on protocol implementations.
 */
#define DEFINE_PROTOCOL_VTABLE(name)                    \
  const struct protocol_vtable name##_vtable = {        \
    #name,                                              \
    name##_init, name##_fini,                           \
    name##_create, name##_destroy,                      \
    name##_handshake, name##_send, name##_recv          \
  }

protocol_params_t *proto_params_init(int n_options,
                                     const char *const *options);
void proto_params_free(protocol_params_t *params);

protocol_t *proto_create(protocol_params_t *params);
void proto_destroy(protocol_t *proto);

int proto_handshake(protocol_t *proto, void *buf);
int proto_send(protocol_t *proto, void *source, void *dest);
enum recv_ret proto_recv(protocol_t *proto, void *source, void *dest);

extern const protocol_vtable *const supported_protocols[];
extern const size_t n_supported_protocols;

#endif
