/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>   /* for size_t */
#include "network.h"  /* for recv_ret */

struct evbuffer;
struct sockaddr;

/**
  This struct defines parameters of a protocol on a per-listener basis.

  By 'per-listener basis' I mean that the parameters defined here will
  be inherited by *all* connections opened from the listener_t that
  owns this protocol_params_t.
*/
typedef struct protocol_params_t {
  const struct protocol_vtable *vtable;
  struct sockaddr *target_address;
  struct sockaddr *listen_address;
  char *shared_secret;
  size_t shared_secret_len;
  size_t target_address_len;
  size_t listen_address_len;
  int mode;
} protocol_params_t;

/**
   This protocol specific struct defines the state of the protocol
   on a per-connection basis.

   By 'protocol specific' I mean that every protocol has its own
   state struct. (for example, obfs2 has obfs2_state_t).  A protocol_t
   struct is always the first member of this struct, and vtable->create
   returns that member (standard fake-inheritance-in-C technique).
   All data other than the vtable is hidden from everything but the
   protocol implementation.

   By 'per-connection basis' I mean that the every connection has a
   different protocol_t struct, and that's precisely the reason that
   this struct is owned by the conn_t struct.
 */
struct protocol_t {
  const struct protocol_vtable *vtable;
};

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

  /** Initialization function: Allocate a 'protocol_params_t' object
      and fill it in from the provided 'options' array. */
  struct protocol_params_t *(*init)(int n_options,
                                    const char *const *options);

  /** Constructor: Allocates per-connection, protocol-specific state. */
  struct protocol_t *(*create)(struct protocol_params_t *params);

  /** Destructor: Destroys per-connection, protocol-specific state.  */
  void (*destroy)(struct protocol_t *state);

  /** Perform a connection handshake. Not all protocols have a handshake. */
  int (*handshake)(struct protocol_t *state,
                   struct evbuffer *buf);

  /** Send data coming downstream from 'source' along to 'dest'. */
  int (*send)(struct protocol_t *state,
              struct evbuffer *source,
              struct evbuffer *dest);

  /** Receive data from 'source' and pass it upstream to 'dest'. */
  enum recv_ret (*recv)(struct protocol_t *state,
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
    name##_init, name##_create, name##_destroy,         \
    name##_handshake, name##_send, name##_recv          \
  }

struct protocol_params_t *proto_params_init(int n_options,
                                            const char *const *options);
void proto_params_free(protocol_params_t *params);

struct protocol_t *proto_create(struct protocol_params_t *params);
void proto_destroy(struct protocol_t *proto);

int proto_handshake(struct protocol_t *proto, void *buf);
int proto_send(struct protocol_t *proto, void *source, void *dest);
enum recv_ret proto_recv(struct protocol_t *proto, void *source, void *dest);

extern const protocol_vtable *const supported_protocols[];
extern const size_t n_supported_protocols;

#endif
