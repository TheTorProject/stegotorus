/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#ifndef STEG_H
#define STEG_H

/** A steganography instance must define a private subclass of this
    type, that implements all of the methods below, plus a descendant
    constructor.  The subclass must have exactly the same name that
    you use for the module name in STEG_DEFINE_MODULE, and should be
    declared inside an anonymous namespace.  Use STEG_DECLARE_METHODS
    in the declaration. */
struct steg_t
{
  bool is_clientside : 1;

  steg_t(bool is_clientside) : is_clientside(is_clientside) {}
  virtual ~steg_t();

  /** Report the name of this steg module.  You do not have to define
      this method in your subclass, STEG_DEFINE_MODULE does it for you. */
  virtual const char *name() = 0;

  /** Report the maximum number of bytes that could be transmitted on
      connection CONN at this time.  You must be prepared to handle a
      subsequent request to transmit any _smaller_ number of bytes on
      this connection.  */
  virtual size_t transmit_room(conn_t *conn) = 0;

  /** Consume all of the data in SOURCE, disguise it, and write it to
      the outbound buffer for CONN. Return 0 on success, -1 on failure. */
  virtual int transmit(struct evbuffer *source, conn_t *conn) = 0;

  /** The data in CONN's inbound buffer should have been disguised by
      the peer instance to STATE.  Unmask it and write it to DEST.
      Return 0 on success, -1 on failure.  If more data needs to come
      over the wire before anything can be unmasked, that is *not* a
      failure condition; return 0, but do not consume any data or
      write anything to DEST.  It is *preferable*, but not currently
      *required*, for this method to not consume any data or write
      anything to DEST in a failure situation. */
  virtual int receive(conn_t *conn, struct evbuffer *dest) = 0;
};

/** STEG_DEFINE_MODULE defines an object with this type, plus the
    function that it points to.  You don't ever manipulate this object
    directly; however, read its documentation to understand the
    arguments to STEG_DEFINE_MODULE. */

struct steg_module
{
  /** Name of the steganography module. Must be a valid C identifier. */
  const char *name;

  /** Create an appropriate steg_t subclass for this module.
      More arguments may be added later.  */
  steg_t *(*new_)(bool is_clientside);
};

extern const steg_module *const supported_stegs[];

int steg_is_supported(const char *name);
steg_t *steg_new(const char *name, bool is_clientside);

/* Macros for use in defining steg modules. */

#define STEG_DEFINE_MODULE(mod)                 \
  /* new_ dispatchers */                        \
  static steg_t *mod##_new(bool is_clientside)  \
  { return new mod(is_clientside); }            \
                                                \
  /* canned methods */                          \
  const char *mod::name() { return #mod; }      \
                                                \
  /* module object */                           \
  extern const steg_module s_mod_##mod = {      \
    #mod, mod##_new                             \
  } /* deliberate absence of semicolon */

#define STEG_DECLARE_METHODS(mod)                               \
  mod(bool is_clientside);                                      \
  virtual ~mod();                                               \
  virtual const char *name();                                   \
  virtual size_t transmit_room(conn_t *conn);                   \
  virtual int transmit(struct evbuffer *source, conn_t *conn);  \
  virtual int receive(conn_t *conn, struct evbuffer *dest)      \
  /* deliberate absence of semicolon */

#endif
