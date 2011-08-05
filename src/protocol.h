/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

/**
   This struct defines a "configuration" of the proxy.
   A configuration is a set of addresses to listen on, and what to do
   when connections are received.  Almost all of a configuration is
   protocol-private data, stored in the larger structure in which this
   struct is embedded.
 */
struct config_t
{
  const struct protocol_vtable *vtable;
};

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

  /** Allocate a 'config_t' object and fill it in from the provided
      'options' array. */
  config_t *(*config_create)(int n_options, const char *const *options);

  /** Destroy the provided 'config_t' object.  */
  void (*config_free)(config_t *cfg);

  /** Return a set of addresses to listen on, in the form of an
      'evutil_addrinfo' linked list.  There may be more than one list;
      users of this function should call it repeatedly with successive
      values of N, starting from zero, until it returns NULL, and
      create listeners for every address returned. */
  struct evutil_addrinfo *(*config_get_listen_addrs)(config_t *cfg, size_t n);

  /** Return a set of addresses to attempt an outbound connection to,
      in the form of an 'evutil_addrinfo' linked list.  There is only
      one such list. */
  struct evutil_addrinfo *(*config_get_target_addr)(config_t *cfg);

  /** A connection has just been made to one of 'cfg's listener
      addresses.  Return an extended 'conn_t' object, filling in the
      'cfg' and 'mode' fields of the generic structure.  */
  conn_t *(*conn_create)(config_t *cfg);

  /** Destroy per-connection, protocol-specific state.  */
  void (*conn_free)(conn_t *conn);

  /** Perform a connection handshake. Not all protocols have a handshake. */
  int (*handshake)(conn_t *conn);

  /** Send data coming from the upstream 'source' along to 'dest'. */
  int (*send)(conn_t *dest, struct evbuffer *source);

  /** Receive data from 'source' and pass it upstream to 'dest'. */
  enum recv_ret (*recv)(conn_t *source, struct evbuffer *dest);

  /* The remaining methods are only required if your protocol makes
     use of steganography modules.  If you provide them, they must be
     effective. */

  /** It is an error if any further data is received from the remote
      peer on this connection. */
  void (*expect_close)(conn_t *conn);

  /** It is an error to transmit any further data to the remote peer
      on this connection.  However, the peer may still send data back. */
  void (*cease_transmission)(conn_t *conn);

  /** After all pending data is transmitted, close this connection.
      (This is stronger than cease_transmission - no reply is expected.) */
  void (*close_after_transmit)(conn_t *conn);

  /** If TIMEOUT milliseconds elapse without anything having been
      transmitted on this connection, you need to make up some data
      and send it.  */
  void (*transmit_soon)(conn_t *conn, unsigned long timeout);
};

/**
   Use this macro to define protocol_vtable objects; it ensures all
   the methods are in the correct order and enforces a consistent
   naming convention on protocol implementations.
 */

#define PROTOCOL_VTABLE_COMMON_METHODS(name)    \
    #name,                                      \
    name##_config_create,                       \
    name##_config_free,                         \
    name##_config_get_listen_addrs,             \
    name##_config_get_target_addr,              \
    name##_conn_create,                         \
    name##_conn_free,                           \
    name##_handshake, name##_send, name##_recv  \

#define DEFINE_PROTOCOL_VTABLE_NOSTEG(name)     \
  const protocol_vtable name##_vtable = {       \
    PROTOCOL_VTABLE_COMMON_METHODS(name),       \
    NULL, NULL, NULL, NULL,                     \
  }

#define DEFINE_PROTOCOL_VTABLE_STEG(name)       \
  const protocol_vtable name##_vtable = {       \
    PROTOCOL_VTABLE_COMMON_METHODS(name),       \
    name##_expect_close,                        \
    name##_cease_transmission,                  \
    name##_close_after_transmit,                \
    name##_transmit_soon,                       \
  }

config_t *config_create(int n_options, const char *const *options);
void config_free(config_t *cfg);

struct evutil_addrinfo *config_get_listen_addrs(config_t *cfg, size_t n);
struct evutil_addrinfo *config_get_target_addr(config_t *cfg);

conn_t *proto_conn_create(config_t *cfg);
void proto_conn_free(conn_t *conn);

int proto_handshake(conn_t *conn);
int proto_send(conn_t *dest, struct evbuffer *source);
enum recv_ret proto_recv(conn_t *source, struct evbuffer *dest);

extern const protocol_vtable *const supported_protocols[];
extern const size_t n_supported_protocols;

#endif
