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
  const struct proto_vtable *vtable;
  enum listen_mode           mode;
};

config_t *config_create(int n_options, const char *const *options);
void config_free(config_t *cfg);

struct evutil_addrinfo *config_get_listen_addrs(config_t *cfg, size_t n);
struct evutil_addrinfo *config_get_target_addr(config_t *cfg);


/**
   This struct defines a protocol and its methods; note that not all
   of them are methods on the same object in the C++ sense.

   A filled-in, statically allocated proto_vtable object is the
   principal interface between each individual protocol and generic
   code.  At present there is a static list of these objects in protocol.c.
 */
struct proto_vtable
{
  /** The short name of this protocol. Must be a valid C identifier. */
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

  /** Return an extended 'circuit_t' object based on the configuration 'cfg'.
      Must fill in the 'cfg' field of the generic structure. */
  circuit_t *(*circuit_create)(config_t *cfg);

  /** Destroy per-circuit, protocol-specific state. */
  void (*circuit_free)(circuit_t *ckt);

  /** Return an extended 'conn_t' object based on the configuration 'cfg'.
      Must fill in the 'cfg' field of the generic structure.  */
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

extern const proto_vtable *const supported_protocols[];
extern const size_t n_supported_protocols;

/** Use these macros to define protocol modules; they ensure all the
    methods are in the correct order in the vtable, enforce a
    consistent naming convention on protocol implementations, and
    provide type-safe up and down casts. */

#define PROTO_VTABLE_COMMON(name)               \
    #name,                                      \
    name##_config_create,                       \
    name##_config_free,                         \
    name##_config_get_listen_addrs,             \
    name##_config_get_target_addr,              \
    name##_circuit_create,                      \
    name##_circuit_free,                        \
    name##_conn_create,                         \
    name##_conn_free,                           \
    name##_handshake,                           \
    name##_send,                                \
    name##_recv,

#define PROTO_VTABLE_NOSTEG(name)               \
    NULL, NULL, NULL, NULL,

#define PROTO_VTABLE_STEG(name)                 \
    name##_expect_close,                        \
    name##_cease_transmission,                  \
    name##_close_after_transmit,                \
    name##_transmit_soon,

#define PROTO_FWD_COMMON(name)                                          \
  static config_t *name##_config_create(int, const char *const *);      \
  static void name##_config_free(config_t *);                           \
  static struct evutil_addrinfo *                                       \
    name##_config_get_listen_addrs(config_t *, size_t);                 \
  static struct evutil_addrinfo *                                       \
    name##_config_get_target_addr(config_t *);                          \
  static circuit_t *name##_circuit_create(config_t *);                  \
  static void name##_circuit_free(circuit_t *);                         \
  static conn_t *name##_conn_create(config_t *);                        \
  static void name##_conn_free(conn_t *);                               \
  static int name##_handshake(conn_t *);                                \
  static int name##_send(conn_t *, struct evbuffer *);                  \
  static enum recv_ret name##_recv(conn_t *, struct evbuffer *);

#define PROTO_FWD_NOSTEG(name) /* nothing required */

#define PROTO_FWD_STEG(name)                                    \
  static void name##_expect_close(conn_t *);                    \
  static void name##_cease_transmission(conn_t *);              \
  static void name##_close_after_transmit(conn_t *);            \
  static void name##_transmit_soon(conn_t *, unsigned long);

#define PROTO_CAST_HELPERS(name)                                \
  static inline config_t *upcast_config(name##_config_t *c)     \
  { return &c->super; }                                         \
  static inline name##_config_t *downcast_config(config_t *c)   \
  { return DOWNCAST(name##_config_t, super, c); }               \
  static inline conn_t *upcast_conn(name##_conn_t *c)           \
  { return &c->super; }                                         \
  static inline name##_conn_t *downcast_conn(conn_t *c)         \
  { return DOWNCAST(name##_conn_t, super, c); }                 \
  static inline circuit_t *upcast_circuit(name##_circuit_t *c)  \
  { return &c->super; }                                         \
  static inline name##_circuit_t *downcast_circuit(circuit_t *c)\
  { return DOWNCAST(name##_circuit_t, super, c); }

#define PROTO_DEFINE_MODULE(name, stegp)        \
  PROTO_CAST_HELPERS(name)                      \
  PROTO_FWD_COMMON(name)                        \
  PROTO_FWD_##stegp(name)                       \
                                                \
  const proto_vtable p_##name##_vtable = {      \
    PROTO_VTABLE_COMMON(name)                   \
    PROTO_VTABLE_##stegp(name)                  \
  } /* deliberate absence of semicolon */

#endif
