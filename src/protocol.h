/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * Copyright 2012, 2013 Tor Project Inc.
 * See LICENSE for other credits and copying information
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "cpp.h"
#include <string>
#include <map>

#include <yaml-cpp/yaml.h>

struct proto_module;
struct steg_config_t;

/** 
    Because it is the protocol which process user command line data 
    it needs a way to convey the config to the steg modules. a map 
    of [steg module name] to list of steg_mod_user_config_t object 
    serves this purpose. 
*/

typedef std::map<std::string, std::string> user_config_dict_t;
/** A 'config_t' is a set of addresses to listen on, and what to do
    when connections are received.  A protocol module must define a
    private subclass of this type that implements all the methods
    below, plus a descendant constructor.  The subclass must have the
    name MODULE_config_t where MODULE is the module name you use in
    PROTO_DEFINE_MODULE. Use CONFIG_DECLARE_METHODS in the
    declaration. */

struct config_t
{
  struct event_base         *base;
  enum listen_mode           mode;
  /* stopgap, see create_outbound_connections_socks */
  bool ignore_socks_destination : 1;

  std::map<std::string, user_config_dict_t> steg_mod_user_configs;

  config_t() : base(0), mode((enum listen_mode)-1) {}
  virtual ~config_t();

    DISALLOW_COPY_AND_ASSIGN(config_t);

  /** Return the name of the protocol associated with this
      configuration.  You do not have to define this method in your
      subclass, PROTO_DEFINE_MODULE does it for you. */
  virtual const char *name() const = 0;

  /** 
      Initialize yourself from a set of command line options.  This is
      separate from the subclass constructor so that it can fail:

      @param n_opts number of command line parameters
      @param opts pointer to the array of char* of parameters value

      @return if the command line options are ill-formed, print a diagnostic
      on stderr and return false.  On success, return true. 
  */
  virtual bool init(unsigned int n_opts, const char *const *opts) = 0;

  /** Return a set of addresses to listen on, in the form of an
      'evutil_addrinfo' linked list.  There may be more than one list;
      users of this function should call it repeatedly with successive
      values of N, starting from zero, until it returns NULL, and
      create listeners for every address returned. */
  virtual evutil_addrinfo *get_listen_addrs(size_t n) const = 0;

  /** Return a set of addresses to attempt an outbound connection to,
      in the form of an 'evutil_addrinfo' linked list.  As with
      get_listen_addrs, there may be more than one such list; users
      should in general attempt simultaneous connection to at least
      one address from every list.  The maximum N is indicated in the
      same way as for get_listen_addrs.  */
  virtual evutil_addrinfo *get_target_addrs(size_t n) const = 0;

  /** Return the steganography module associated with either listener
      or target address set N.  If called on a protocol that doesn't
      use steganography, will return NULL.  */
  virtual const steg_config_t *get_steg(size_t n) const = 0;

  /** Return an extended 'circuit_t' object for a new socket using
      this configuration.  The 'index' argument is equal to the 'N'
      argument to get_listen_addrs or get_target_addrs that retrieved
      the address to which the socket is bound.  */
  virtual circuit_t *circuit_create(size_t index) = 0;

  /** Return an extended 'conn_t' object for a new socket using this
      configuration.  The 'index' argument is equal to the 'N'
      argument to get_listen_addrs or get_target_addrs that retrieved
      the address to which the socket is bound.  */
  virtual conn_t *conn_create(size_t index) = 0;
};

int config_is_supported(const char *name);
config_t *config_create(int n_options, const char *const *options);
config_t *config_create(const YAML::Node& protocols_node);

/** PROTO_DEFINE_MODULE defines an object with this type, plus the
    function that it points to; there is a table of all such objects,
    which generic code uses to know what protocols are available. */
struct proto_module
{
  /** Name of this protocol. Must be a valid C identifier. */
  const char *name;

  /** Create a config_t instance for this module from a set of command
      line options. */
  config_t *(*config_create)(int n_options, const char *const *options);

  /** */
  /**
     Create a config_t instance for this module from the protocol config dictionary
      created from config file. Its overload of config_create but using the YAML Node
     in the config file

     @param protocol_node reference to the node defining the prtocol spec in the
          config file
  */
  config_t *(*config_create_from_yaml)(const YAML::Node& protocols_node);
};

extern const proto_module *const supported_protos[];

/** Use these macros to define protocol modules. */

#define PROTO_DEFINE_MODULE(mod)                                \
  /* canned methods */                                          \
  const char *mod##_config_t::name() const                      \
  { return #mod; }                                              \
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
  static config_t *                                             \
  mod##_config_create(const YAML::Node& protocol_node)          \
  { mod##_config_t *s = new mod##_config_t();                   \
    if (s->init(protocol_node))                                 \
      return s;                                                 \
    delete s;                                                   \
    return 0;                                                   \
  }                                                             \
                                                                \
  extern const proto_module p_mod_##mod = {                     \
    #mod, mod##_config_create, mod##_config_create              \
    /* intelligent casting based on the type of pointer */      \
  } /* deliberate absence of semicolon */                       
                                                                
#define CONFIG_DECLARE_METHODS(mod)                             \
  mod##_config_t();                                             \
  virtual ~mod##_config_t();                                    \
  virtual const char *name() const;                             \
  virtual bool init(unsigned int n_opts, const char *const *opts); \
  virtual bool init(const YAML::Node& protocols_node);               \
  virtual evutil_addrinfo *get_listen_addrs(size_t n) const;    \
  virtual evutil_addrinfo *get_target_addrs(size_t n) const;    \
  virtual const steg_config_t *get_steg(size_t n) const;        \
  virtual circuit_t *circuit_create(size_t index);              \
  virtual conn_t *conn_create(size_t index)                     \
  /* deliberate absence of semicolon */

#define CONFIG_STEG_STUBS(mod)                                  \
  const steg_config_t *mod##_config_t::get_steg(size_t) const   \
  { return 0; }

#define CONN_DECLARE_METHODS(mod)                       \
  mod##_conn_t();                                       \
  virtual ~mod##_conn_t();                              \
  virtual void close();                                 \
  virtual circuit_t *circuit() const;                   \
  virtual int  maybe_open_upstream();                   \
  virtual int  handshake();                             \
  virtual int  recv();                                  \
  virtual int  recv_eof();                              \
  virtual void expect_close();                          \
  virtual void cease_transmission();                    \
  virtual void transmit_soon(unsigned long timeout)     \
  /* deliberate absence of semicolon */

#define CONN_STEG_STUBS(mod)                            \
  void mod##_conn_t::expect_close()                     \
  { log_abort(this, "steg stub called"); }              \
  void mod##_conn_t::cease_transmission()               \
  { log_abort(this, "steg stub called"); }              \
  void mod##_conn_t::transmit_soon(unsigned long)       \
  { log_abort(this, "steg stub called"); }

#define CIRCUIT_DECLARE_METHODS(mod)            \
  mod##_circuit_t();                            \
  virtual ~mod##_circuit_t();                   \
  virtual void close();                         \
  virtual config_t *cfg() const;                \
  virtual void add_downstream(conn_t *);        \
  virtual void drop_downstream(conn_t *);       \
  virtual int  send();                          \
  virtual int send_eof();

#endif
