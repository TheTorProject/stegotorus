/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

struct proto_module;

/** A 'config_t' is a set of addresses to listen on, and what to do
    when connections are received.  A protocol module must define a
    private subclass of this type that implements all the methods
    below, plus a descendant constructor.  The subclass must have the
    name MODULE_config_t where MODULE is the module name you use in
    PROTO_DEFINE_MODULE.  Use CONFIG_DECLARE_METHODS in the
    declaration. */

struct config_t
{
  struct event_base         *base;
  enum listen_mode           mode;
  /* stopgap, see create_outbound_connections_socks */
  bool ignore_socks_destination : 1;

  config_t() : base(0), mode((enum listen_mode)-1) {}
  virtual ~config_t();

  /** Return the protocol module object associated with this
      configuration.  You do not have to define this method in your
      subclass, PROTO_DEFINE_MODULE does it for you. */
  virtual const proto_module *vtable() = 0;

  /** Initialize yourself from a set of command line options.  This is
      separate from the subclass constructor so that it can fail:
      if the command line options are ill-formed, print a diagnostic
      on stderr and return false.  On success, return true. */
  virtual bool init(int n_opts, const char *const *opts) = 0;

  /** Return a set of addresses to listen on, in the form of an
      'evutil_addrinfo' linked list.  There may be more than one list;
      users of this function should call it repeatedly with successive
      values of N, starting from zero, until it returns NULL, and
      create listeners for every address returned. */
  virtual evutil_addrinfo *get_listen_addrs(size_t n) = 0;

  /** Return a set of addresses to attempt an outbound connection to,
      in the form of an 'evutil_addrinfo' linked list.  As with
      get_listen_addrs, there may be more than one such list; users
      should in general attempt simultaneous connection to at least
      one address from every list.  The maximum N is indicated in the
      same way as for get_listen_addrs.  */
  virtual evutil_addrinfo *get_target_addrs(size_t n) = 0;

  /** Return an extended 'circuit_t' object for a new socket using
      this configuration.  Must fill in the 'cfg' field of the generic
      structure.  */
  virtual circuit_t *circuit_create() = 0;

  /** Return an extended 'conn_t' object for a new socket using this
      configuration.  Must fill in the 'cfg' field of the generic
      structure.  */
  virtual conn_t *conn_create() = 0;
};

int config_is_supported(const char *name);
config_t *config_create(int n_options, const char *const *options);

/**
   This struct defines a protocol and its methods; note that not all
   of them are methods on the same object in the C++ sense.
   See connections.h for the definitions of 'conn_t' and 'circuit_t'.

   A filled-in, statically allocated proto_module object is the
   principal interface between each individual protocol and generic code.
 */
struct proto_module
{
  /** The short name of this protocol. Must be a valid C identifier. */
  const char *name;

  /** Create an appropriate config_t instance for this module from a
      set of command line options. */
  config_t *(*config_create)(int n_options, const char *const *options);

  /** Destroy per-circuit, protocol-specific state. */
  void (*circuit_free)(circuit_t *ckt);

  /** Add a downstream connection to this circuit. */
  void (*circuit_add_downstream)(circuit_t *ckt, conn_t *conn);

  /** Drop a downstream connection which is no longer usable. */
  void (*circuit_drop_downstream)(circuit_t *ckt, conn_t *conn);

  /** Transmit data from the upstream to the downstream peer. */
  int (*circuit_send)(circuit_t *ckt);

  /** Transmit any buffered data and an EOF indication to the downstream
      peer.  This will only be called once per circuit, and circuit_send
      will not be called again after this has been called; if you need
      periodic "can we flush more data now?" callbacks, and conn_recv
      events won't do it, you have to set them up yourself. */
  int (*circuit_send_eof)(circuit_t *ckt);

  /** Destroy per-connection, protocol-specific state.  */
  void (*conn_free)(conn_t *conn);

  /** Create an upstream circuit for this connection, if it is
      possible to do so without receiving data from the downstream
      peer.  If data must be received first, this method should do
      nothing (but return success), and the |conn_recv| method is
      responsible for creating the upstream circuit when appropriate.
      Must return 0 on success, -1 on failure. */
  int (*conn_maybe_open_upstream)(conn_t *conn);

  /** Perform a connection handshake. Not all protocols have a handshake. */
  int (*conn_handshake)(conn_t *conn);

  /** Receive data from 'source' and pass it upstream (to the circuit). */
  int (*conn_recv)(conn_t *source);

  /** Take any actions necessary upon receipt of an end-of-transmission
      indication from the remote peer.  Note that this is _not_
      necessarily the same as "end of file" at the circuit level,
      depending on the protocol.  */
  int (*conn_recv_eof)(conn_t *source);

  /* The remaining methods are only required if your protocol makes
     use of steganography modules.  If you provide them, they must be
     effective. */

  /** It is an error if any further data is received from the remote
      peer on this connection. */
  void (*conn_expect_close)(conn_t *conn);

  /** It is an error to transmit any further data to the remote peer
      on this connection.  However, the peer may still send data back. */
  void (*conn_cease_transmission)(conn_t *conn);

  /** After all pending data is transmitted, close this connection.
      (This is stronger than cease_transmission - no reply is expected.) */
  void (*conn_close_after_transmit)(conn_t *conn);

  /** If TIMEOUT milliseconds elapse without anything having been
      transmitted on this connection, you need to make up some data
      and send it.  */
  void (*conn_transmit_soon)(conn_t *conn, unsigned long timeout);
};

extern const proto_module *const supported_protos[];

/** Use these macros to define protocol modules; they ensure all the
    methods are in the correct order in the vtable, enforce a
    consistent naming convention on protocol implementations, and
    provide type-safe up and down casts. */

#define PROTO_VTABLE_COMMON(name)               \
    #name,                                      \
    name##_config_create,                       \
    name##_circuit_free,                        \
    name##_circuit_add_downstream,              \
    name##_circuit_drop_downstream,             \
    name##_circuit_send,                        \
    name##_circuit_send_eof,                    \
    name##_conn_free,                           \
    name##_conn_maybe_open_upstream,            \
    name##_conn_handshake,                      \
    name##_conn_recv,                           \
    name##_conn_recv_eof,

#define PROTO_VTABLE_NOSTEG(name)               \
    NULL, NULL, NULL, NULL,

#define PROTO_VTABLE_STEG(name)                 \
    name##_conn_expect_close,                   \
    name##_conn_cease_transmission,             \
    name##_conn_close_after_transmit,           \
    name##_conn_transmit_soon,

#define PROTO_FWD_COMMON(name)                                          \
  static void name##_circuit_free(circuit_t *);                         \
  static void name##_circuit_add_downstream(circuit_t *, conn_t *);     \
  static void name##_circuit_drop_downstream(circuit_t *, conn_t *);    \
  static int name##_circuit_send(circuit_t *);                          \
  static int name##_circuit_send_eof(circuit_t *);                      \
  static void name##_conn_free(conn_t *);                               \
  static int name##_conn_maybe_open_upstream(conn_t *);                 \
  static int name##_conn_handshake(conn_t *);                           \
  static int name##_conn_recv(conn_t *);                                \
  static int name##_conn_recv_eof(conn_t *);

#define PROTO_FWD_NOSTEG(name) /* nothing required */

#define PROTO_FWD_STEG(name)                                            \
  static void name##_conn_expect_close(conn_t *);                       \
  static void name##_conn_cease_transmission(conn_t *);                 \
  static void name##_conn_close_after_transmit(conn_t *);               \
  static void name##_conn_transmit_soon(conn_t *, unsigned long);

#define PROTO_CAST_HELPERS(name)                                \
  static inline conn_t *upcast_conn(name##_conn_t *c)           \
  { return &c->super; }                                         \
  static inline name##_conn_t *downcast_conn(conn_t *c)         \
  { return DOWNCAST(name##_conn_t, super, c); }                 \
  static inline circuit_t *upcast_circuit(name##_circuit_t *c)  \
  { return &c->super; }                                         \
  static inline name##_circuit_t *downcast_circuit(circuit_t *c)\
  { return DOWNCAST(name##_circuit_t, super, c); }

#define PROTO_DEFINE_MODULE(mod, stegp)                         \
  extern const proto_module p_mod_##mod;                        \
                                                                \
  PROTO_CAST_HELPERS(mod)                                       \
  PROTO_FWD_COMMON(mod)                                         \
  PROTO_FWD_##stegp(mod)                                        \
                                                                \
  /* canned methods */                                          \
  const proto_module *mod##_config_t::vtable()                  \
  { return &p_mod_##mod; }                                      \
                                                                \
  static config_t *                                             \
  mod##_config_create(int n_opts, const char *const *opts)      \
  { mod##_config_t *s = new mod##_config_t();                   \
    if (s->init(n_opts, opts))                                  \
      return s;                                                 \
    delete s;                                                   \
    return 0;                                                   \
  }                                                             \
                                                                \
  extern const proto_module p_mod_##mod = {                     \
    PROTO_VTABLE_COMMON(mod)                                    \
    PROTO_VTABLE_##stegp(mod)                                   \
  } /* deliberate absence of semicolon */

#define CONFIG_DECLARE_METHODS(mod)                             \
  mod##_config_t();                                             \
  virtual ~mod##_config_t();                                    \
  virtual const proto_module *vtable();                         \
  virtual bool init(int n_opts, const char *const *opts);       \
  virtual evutil_addrinfo *get_listen_addrs(size_t n);          \
  virtual evutil_addrinfo *get_target_addrs(size_t n);          \
  virtual circuit_t *circuit_create();                          \
  virtual conn_t *conn_create()                                 \
  /* deliberate absence of semicolon */

#endif
