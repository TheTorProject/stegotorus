/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011 SRI International
 * See LICENSE for other credits and copying information
 */

#include <event2/buffer.h>
#include <event2/event.h>

#include <string>

#include "util.h"
#include "connections.h"
#include "protocol.h"


namespace {
  struct null_config_t : config_t
  {
    config_dict_t null_user_config;

    struct evutil_addrinfo *listen_addr;
    struct evutil_addrinfo *target_addr;

    /**
     * using the protocol dictionary provides a uniform init which can
     * be called by both init functions which has populated the config
     * dict
     */
    bool init_from_protocol_config_dict();


    CONFIG_DECLARE_METHODS(null);
  };

  struct null_circuit_t;

  struct null_conn_t : conn_t
  {
    null_config_t *config;
    null_circuit_t *upstream;

    CONN_DECLARE_METHODS(null);
  };

  struct null_circuit_t : circuit_t
  {
    null_config_t *config;
    null_conn_t *downstream;

    CIRCUIT_DECLARE_METHODS(null);
  };
}

PROTO_DEFINE_MODULE(null);

null_config_t::null_config_t()
{
}

null_config_t::~null_config_t()
{
  if (this->listen_addr)
    evutil_freeaddrinfo(this->listen_addr);
  if (this->target_addr)
    evutil_freeaddrinfo(this->target_addr);
}

bool
null_config_t::init(unsigned int n_options, const char *const *options)
{
  if (n_options < 2)
    goto usage;

  null_user_config["mode"] = options[0];
  null_user_config["listen-address"] = options[1];

  if (null_user_config["mode"] != "socks") {
    if (n_options != 3)
      goto usage;

    null_user_config["target-address"] = options[2];
  } else {//socks
    if (n_options != 2)
      goto usage;
  }

  if (!init_from_protocol_config_dict())
    goto usage;

  return true;

 usage:
  log_warn("null syntax:\n"
           "\tnull <mode> <listen_address> [<target_address>]\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tlisten_address, target_address ~ host:port\n"
           "\ttarget_address is required for server and client mode,\n"
           "\tand forbidden for socks mode.\n"
           "Examples:\n"
           "\tstegotorus null socks 127.0.0.1:5000\n"
           "\tstegotorus null client 127.0.0.1:5000 192.168.1.99:11253\n"
           "\tstegotorus null server 192.168.1.99:11253 127.0.0.1:9005");
  return false;
}

/**
 * read the protocol parameters from the YAML configs
 * and store them in the null_user_config.
 * abort if config has problem.
 *
 * @param protocols_node the YAML node which points to protocols:
 *        node in the config file
 */
bool null_config_t::init(const YAML::Node& protocol_node)
{
  //to be send to the steg mods during creation
  try {
      for(auto cur_protocol_field: protocol_node) {
        //if it is the protocol stegs config we need to store the config node
        //to create the steg protocol later, cause the steg protocol might
        //need access to the protocol options
        std::string current_field_name = cur_protocol_field.first.as<std::string>();
        if (!(
            (current_field_name == "mode") ||
            (current_field_name == "listen-address") ||
            (current_field_name == "target-address")
              )) {
          log_warn("invalid config keyword %s", current_field_name.c_str());
          return false;
        }
          null_user_config[current_field_name] = cur_protocol_field.second.as<std::string>();

      }
  }  catch( YAML::RepresentationException &e ) {
    log_warn("bad config format %s", ((std::string)e.what()).c_str());
    return false;

  }

  return init_from_protocol_config_dict();

}

bool null_config_t::init_from_protocol_config_dict()
{
  const char* defport;

  //this also verify that the config dict is already populated
  if (null_user_config["mode"] == "client") {
    defport = "48988"; // bf5c
    mode = LSN_SIMPLE_CLIENT;
  } else if (null_user_config["mode"] == "socks") {
    defport = "23548"; // 5bf5
    mode = LSN_SOCKS_CLIENT;
  } else if (null_user_config["mode"] == "server") {
    defport = "11253"; // 2bf5
    mode = LSN_SIMPLE_SERVER;
  } else {
    log_warn("invalid mode %s for protocol null", null_user_config["mode"].c_str());
    return false;
  }

  this->listen_addr = resolve_address_port(null_user_config["listen-address"].c_str(), 1, 1, defport);
  if (!this->listen_addr) {
    log_warn("bad listen address %s", null_user_config["listen-address"].c_str());
    return false;
  }

  if (mode != LSN_SOCKS_CLIENT) {
    this->target_addr = resolve_address_port(null_user_config["target-address"].c_str(), 1, 0, NULL);
    if (!this->target_addr) {
      log_warn("bad target address %s", null_user_config["target-address"].c_str());
      return false;
    }
  } else if ((null_user_config.find("target-address") != null_user_config.end())) {
    //sanity check: make sure user hasn't specified a target address by mistake
    log_warn("target-address %s is specified but mode %s does not need one.", null_user_config["target-address"].c_str(), null_user_config["mode"].c_str());
    return false;
  }

  return true;

}
/** Retrieve the 'n'th set of listen addresses for this configuration. */
struct evutil_addrinfo *
null_config_t::get_listen_addrs(size_t n) const
{
  if (n > 0)
    return 0;
  return this->listen_addr;
}

/* Retrieve the target address for this configuration. */
struct evutil_addrinfo *
null_config_t::get_target_addrs(size_t n) const
{
  if (n > 0)
    return 0;
  return this->target_addr;
}

/* Create a circuit object. */
circuit_t *
null_config_t::circuit_create(size_t)
{
  null_circuit_t *ckt = new null_circuit_t;
  ckt->config = this;
  return ckt;
}

null_circuit_t::null_circuit_t()
  : downstream(NULL)
{
}

null_circuit_t::~null_circuit_t()
{
}

void
null_circuit_t::close()
{
  if (downstream) {
    /* break the circular reference before deallocating the
       downstream connection */
    downstream->upstream = NULL;
    conn_do_flush(downstream);
    downstream = NULL;
  }

  circuit_t::close();
}

config_t *
null_circuit_t::cfg() const
{
  return this->config;
}

/* Add a connection to this circuit. */
void
null_circuit_t::add_downstream(conn_t *cn)
{
  null_conn_t *conn = dynamic_cast<null_conn_t *>(cn);
  log_assert(conn);
  log_assert(!conn->upstream);
  log_assert(!this->downstream);

  this->downstream = conn;
  conn->upstream = this;

  log_debug(this, "added connection <%d.%d> to %s",
            this->serial, conn->serial, conn->peername);
}

/* Drop a connection from this circuit.  If this happens in this
   protocol, it is because of a network error, and the whole circuit
   should be closed.  */
void
null_circuit_t::drop_downstream(conn_t *cn)
{
  null_conn_t *conn = dynamic_cast<null_conn_t *>(cn);
  log_assert(conn);
  log_assert(this->downstream == conn);
  log_assert(conn->upstream == this);

  log_debug(this, "dropped connection <%d.%d> to %s",
            this->serial, conn->serial, conn->peername);
  this->downstream = NULL;
  conn->upstream = NULL;
  circuit_do_flush(this);
}

/* Send data from the upstream buffer. */
int
null_circuit_t::send()
{
  log_debug(this, "sending %lu bytes",
            (unsigned long)
            evbuffer_get_length(bufferevent_get_input(this->up_buffer)));

  return evbuffer_add_buffer(this->downstream->outbound(),
                             bufferevent_get_input(this->up_buffer));
}

/* Send an EOF on this circuit. */
int
null_circuit_t::send_eof()
{
  if (this->downstream)
    conn_send_eof(this->downstream);
  this->read_eof = true;
  return 0;
}

/*
  This is called everytime we get a connection for the null
  protocol.
*/

conn_t *
null_config_t::conn_create(size_t)
{
  null_conn_t *conn = new null_conn_t;
  conn->config = this;
  return conn;
}

null_conn_t::null_conn_t()
  : upstream(NULL)
{
}

null_conn_t::~null_conn_t()
{
}

void
null_conn_t::close()
{
  if (this->upstream)
    this->upstream->drop_downstream(this);

  conn_t::close();
}

/* Only used by connection callbacks */
circuit_t *
null_conn_t::circuit() const
{
  return upstream;
}

/** Null inbound-to-outbound connections are 1:1 */
int
null_conn_t::maybe_open_upstream()
{
  null_circuit_t *ckt = dynamic_cast<null_circuit_t *>
    (circuit_create(this->config, 0));
  if (!ckt)
    return -1;

  ckt->add_downstream(this);
  circuit_open_upstream(ckt);
  return 0;
}

/** Null has no handshake */
int
null_conn_t::handshake()
{
  return 0;
}

/** Receive data from connection SOURCE */
int
null_conn_t::recv()
{
  log_assert(this->upstream);
  log_debug(this, "receiving %lu bytes",
            (unsigned long)evbuffer_get_length(this->inbound()));
  return evbuffer_add_buffer(bufferevent_get_output(this->upstream->up_buffer),
                             this->inbound());
}

/** Receive EOF from connection SOURCE */
int
null_conn_t::recv_eof()
{
  if (this->upstream) {
    if (evbuffer_get_length(this->inbound()) > 0)
      if (this->recv())
        return -1;

    circuit_recv_eof(this->upstream);
  }
  return 0;
}

CONFIG_STEG_STUBS(null);
CONN_STEG_STUBS(null);
