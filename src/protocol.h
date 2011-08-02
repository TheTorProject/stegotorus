/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

/**
   This struct defines a protocol and its methods; note that not all
   of them are methods on the same object in the C++ sense.

   A filled-in, statically allocated protocol_vtable object is the
   principal interface between each individual protocol and generic
   code.  At present there is a static list of these objects in protocol.c.
 */
struct protocol_vtable
{
  /** The short name of this protocol. */
  const char *name;

  /** Allocate a 'listener_t' object and fill it in from the provided
      'options' array. */
  listener_t *(*listener_create)(int n_options, const char *const *options);

  /** Destroy the provided 'listener_t' object.  This function is
      responsible for deallocating any data that the protocol's
      extended structure points to, and deallocating the object
      itself.  But it is *not* responsible for deallocating the data
      pointed to by the generic 'listener_t'; that's already been done
      by generic code.  */
  void (*listener_free)(listener_t *params);

  /** Allocate per-connection, protocol-specific state. */
  conn_t *(*conn_create)(listener_t *params);

  /** Destroy per-connection, protocol-specific state.  */
  void (*conn_free)(conn_t *state);

  /** Perform a connection handshake. Not all protocols have a handshake. */
  int (*handshake)(conn_t *state, struct evbuffer *buf);

  /** Send data coming downstream from 'source' along to 'dest'. */
  int (*send)(conn_t *state,
              struct evbuffer *source,
              struct evbuffer *dest);

  /** Receive data from 'source' and pass it upstream to 'dest'. */
  enum recv_ret (*recv)(conn_t *state,
                        struct evbuffer *source,
                        struct evbuffer *dest);

};

/**
   Use this macro to define protocol_vtable objects; it ensures all
   the methods are in the correct order and enforces a consistent
   naming convention on protocol implementations.
 */
#define DEFINE_PROTOCOL_VTABLE(name)            \
  const protocol_vtable name##_vtable = {       \
    #name,                                      \
    name##_listener_create,                     \
    name##_listener_free,                       \
    name##_conn_create,                         \
    name##_conn_free,                           \
    name##_handshake, name##_send, name##_recv  \
  }

listener_t *proto_listener_create(int n_options, const char *const *options);
void proto_listener_free(listener_t *lsn);

conn_t *proto_conn_create(listener_t *lsn);
void proto_conn_free(conn_t *conn);

int proto_handshake(conn_t *conn, void *buf);
int proto_send(conn_t *conn, void *source, void *dest);
enum recv_ret proto_recv(conn_t *conn, void *source, void *dest);

extern const protocol_vtable *const supported_protocols[];
extern const size_t n_supported_protocols;

#endif
