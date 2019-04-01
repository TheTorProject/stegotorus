/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
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

  steg_config_t(config_t *c);
  
  virtual ~steg_config_t();

  /** Report the name of this steg module.  You do not have to define
      this method in your subclass, STEG_DEFINE_MODULE does it for you. */
  virtual const char *name() const = 0;

  /** Create an extended 'steg_t' object (see below) from this
      configuration, associated with connection CONN.  */
  virtual steg_t *steg_create(conn_t *conn) = 0;

  /** provides the data that the steg protocol needs
      to communicate to its peer. Chop needs to check this buffer
      before serving the user data as these data have proirities.
  */
  evbuffer* protocol_data_in;
  evbuffer* protocol_data_out;

  /* To protect against statistical analysis stegonographer 
     should make sure that the cover size should at least be
     noise2signal times of the data
     
     However, due to the nature of steg module such as nosteg
     module the steganographer might choose to ignore the 
     directive
  */
  double noise2signal;

  /** If chop receives protocol related data, then it writes
      it in protocol_data then call this function to process it.
      
      @returns the number of data it writes in protocol_data to 
      send as a result of processing

  */
  virtual size_t process_protocol_data()
  {
    /* Don't worry, struct can handle virtual functions */
    /* should never arrive here, probably the client and server
       has misunderstanding about which steg module to use*/
    log_debug("steg protocol does not handle protocol data");
    
    return 0; //This signals that there's no data protocol available
              //to send as the result of the (non)process
  }

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

  /** The protocol using this steg module would like to transmit PREF
      bytes on your connection.  Return an adjusted number of bytes;
      you may adjust down to indicate that you cannot transmit all of
      the available data, or up to indicate that it should be padded.

      Returning zero indicates that your connection cannot transmit at
      all right now; if you do this, transmit() will not be called.
      Returning any nonzero value indicates that you want to transmit
      exactly that number of bytes.  The protocol may or may not call
      transmit() after you return a nonzero value, but if it does, it
      will provide the number of bytes you requested.

      If you return a nonzero value, it MUST be greater than or equal
      to MIN, and less than or equal to MAX.  PREF is guaranteed to be
      in this range already.  */
  virtual size_t transmit_room(size_t pref, size_t min, size_t max) = 0;

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
  steg_config_t *(*new_)(config_t *cfg, const std::vector<std::string>& options);
  steg_config_t *(*new_from_yaml_)(config_t *cfg, const YAML::Node& options);
};

extern const steg_module *const supported_stegs[];

int steg_is_supported(const char *name);
steg_config_t *steg_new(const char *name, config_t *cfg, const std::vector<std::string>& options);
steg_config_t *steg_new(const char *name, config_t *cfg, const YAML::Node& options);

/* Macros for use in defining steg modules. */

#define STEG_DEFINE_MODULE(mod)                         \
  /* new_ dispatchers */                                \
  static steg_config_t *mod##_new(config_t *cfg, const std::vector<std::string>& options)       \
  { return new mod##_steg_config_t(cfg, options); }                    \
  static steg_config_t *mod##_new(config_t *cfg, const YAML::Node& options) \
  { return new mod##_steg_config_t(cfg, options); }                             \
                                                \
  /* canned methods */                                  \
  const char *mod##_steg_config_t::name() const         \
  { return #mod; }                                      \
                                                        \
  /* module object */                                   \
  extern const steg_module s_mod_##mod = {              \
    #mod, mod##_new, mod##_new                          \
  } /* deliberate absence of semicolon */

#define STEG_CONFIG_DECLARE_METHODS(mod)                \
  mod##_steg_config_t(config_t *, const std::vector<std::string>&);     \
  mod##_steg_config_t(config_t *, const YAML::Node& options);               \
  virtual ~mod##_steg_config_t();                       \
  virtual const char *name() const;                     \
  virtual steg_t *steg_create(conn_t *)                 \
    /* deliberate absence of semicolon */

#define STEG_DECLARE_METHODS(mod)                       \
  virtual ~mod##_steg_t();                              \
  virtual steg_config_t *cfg();                         \
  virtual size_t transmit_room(size_t, size_t, size_t); \
  virtual int transmit(struct evbuffer *);              \
  virtual int receive(struct evbuffer *)                \
  /* deliberate absence of semicolon */

#endif
