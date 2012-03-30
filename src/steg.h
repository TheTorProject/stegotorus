/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef STEG_H
#define STEG_H

/** A 'steg_config_t' is analogous to a 'config_t' (see protocol.h);
    it defines cross-connection state for a steganography module.
    (A 'config_t' may be associated with several 'steg_config_t's.)

    A steganography module must define a private subclass of this
    type, that implements all the methods below, plus a descendant
    constructor.  The subclass must have the name MODULE_steg_config_t,
    where MODULE is the module name you use in STEG_DEFINE_MODULE.
    It should be declared inside an anonymous namespace.
    Use STEG_CONFIG_DECLARE_METHODS in the declaration. */

struct steg_t;

struct steg_config_t
{
  struct config_t *cfg;

  steg_config_t(config_t *c) : cfg(c) {}
  virtual ~steg_config_t();

  /** Report the name of this steg module.  You do not have to define
      this method in your subclass, STEG_DEFINE_MODULE does it for you. */
  virtual const char *name() = 0;

  /** Create an extended 'steg_t' object (see below) from this
      configuration, associated with connection CONN.  */
  virtual steg_t *steg_create(conn_t *conn) = 0;
};

/** A 'steg_t' object handles the actual steganography for one
    connection, and is responsible for tracking per-connection
    state for the cover protocol, if any.

    Again, a steganography module must define a private subclass of
    this type, that implements all of the methods below, plus a
    descendant constructor.  The subclass must have the name
    MODULE_steg_t, where MODULE is the module name you use in
    STEG_DEFINE_MODULE.  It should be declared inside an anonymous
    namespace.  Use STEG_DECLARE_METHODS in the declaration. */
struct steg_t
{
  steg_t() {}
  virtual ~steg_t();

  /** Return the steg_config_t from which this steg_t was created. */
  virtual steg_config_t *cfg() = 0;

  /** Report the maximum number of bytes that could be transmitted on
      your connection at this time.  You must be prepared to handle a
      subsequent request to transmit any _smaller_ number of bytes on
      this connection.  */
  virtual size_t transmit_room() = 0;

  /** Consume all of the data in SOURCE, disguise it, and write it to
      the outbound buffer for your connection. Return 0 on success, -1
      on failure. */
  virtual int transmit(struct evbuffer *source) = 0;

  /** Unmask as much of the data in your connection's inbound buffer
      as possible, and write it to DEST.  Return 0 on success, -1 on
      failure.  If more data needs to come over the wire before
      anything can be unmasked, that is *not* a failure condition;
      return 0, but do not consume any data or write anything to DEST.
      It is *preferable*, but not currently *required*, for this
      method to not consume any data or write anything to DEST in a
      failure situation. */
  virtual int receive(struct evbuffer *dest) = 0;
};

/** STEG_DEFINE_MODULE defines an object with this type, plus the
    function that it points to; there is a table of all such objects,
    which generic code uses to know what steganography modules are
    available. */
struct steg_module
{
  /** Name of the steganography module. Must be a valid C identifier. */
  const char *name;

  /** Create an appropriate steg_config_t subclass for this module. */
  steg_config_t *(*new_)(config_t *cfg);
};

extern const steg_module *const supported_stegs[];

int steg_is_supported(const char *name);
steg_config_t *steg_new(const char *name, config_t *cfg);

/* Macros for use in defining steg modules. */

#define STEG_DEFINE_MODULE(mod)                                 \
  /* new_ dispatchers */                                        \
  static steg_config_t *mod##_new(config_t *cfg)                \
  { return new mod##_steg_config_t(cfg); }                      \
                                                                \
  /* canned methods */                                          \
  const char *mod##_steg_config_t::name() { return #mod; }      \
                                                                \
  /* module object */                                           \
  extern const steg_module s_mod_##mod = {                      \
    #mod, mod##_new                                             \
  } /* deliberate absence of semicolon */

#define STEG_CONFIG_DECLARE_METHODS(mod)                        \
  mod##_steg_config_t(config_t *cfg);                           \
  virtual ~mod##_steg_config_t();                               \
  virtual const char *name();                                   \
  virtual steg_t *steg_create(conn_t *conn)                     \
  /* deliberate absence of semicolon */

#define STEG_DECLARE_METHODS(mod)                               \
  virtual ~mod##_steg_t();                                      \
  virtual steg_config_t *cfg();                                 \
  virtual size_t transmit_room();                               \
  virtual int transmit(struct evbuffer *source);                \
  virtual int receive(struct evbuffer *dest)                    \
  /* deliberate absence of semicolon */

#endif
