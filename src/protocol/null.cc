/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"

#include <event2/buffer.h>

namespace {
  struct null_config_t : config_t {
    struct evutil_addrinfo *listen_addr;
    struct evutil_addrinfo *target_addr;

    CONFIG_DECLARE_METHODS(null);
  };

  struct null_conn_t : conn_t {
    CONN_DECLARE_METHODS(null);
  };

  struct null_circuit_t : circuit_t {
    conn_t *downstream;

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
null_config_t::init(int n_options, const char *const *options)
{
  const char* defport;

  if (n_options < 1)
    goto usage;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    this->mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    this->mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    this->mode = LSN_SIMPLE_SERVER;
  } else
    goto usage;

  if (n_options != (this->mode == LSN_SOCKS_CLIENT ? 2 : 3))
    goto usage;

  this->listen_addr = resolve_address_port(options[1], 1, 1, defport);
  if (!this->listen_addr)
    goto usage;

  if (this->mode != LSN_SOCKS_CLIENT) {
    this->target_addr = resolve_address_port(options[2], 1, 0, NULL);
    if (!this->target_addr)
      goto usage;
  }

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

/** Retrieve the 'n'th set of listen addresses for this configuration. */
struct evutil_addrinfo *
null_config_t::get_listen_addrs(size_t n)
{
  if (n > 0)
    return 0;
  return this->listen_addr;
}

/* Retrieve the target address for this configuration. */
struct evutil_addrinfo *
null_config_t::get_target_addrs(size_t n)
{
  if (n > 0)
    return 0;
  return this->target_addr;
}

/* Create a circuit object. */
circuit_t *
null_config_t::circuit_create(size_t)
{
  circuit_t *ckt = new null_circuit_t;
  ckt->cfg = this;
  return ckt;
}

null_circuit_t::null_circuit_t()
{
}

null_circuit_t::~null_circuit_t()
{
  if (downstream) {
    /* break the circular reference before deallocating the
       downstream connection */
    downstream->circuit = NULL;
    delete downstream;
  }
}

/* Add a connection to this circuit. */
void
null_circuit_t::add_downstream(conn_t *conn)
{
  log_assert(!this->downstream);
  this->downstream = conn;
  log_debug(this, "added connection <%d.%d> to %s",
            this->serial, conn->serial, conn->peername);
}

/* Drop a connection from this circuit.  If this happens in this
   protocol, it is because of a network error, and the whole circuit
   should be closed.  */
void
null_circuit_t::drop_downstream(conn_t *conn)
{
  log_assert(this->downstream == conn);
  log_debug(this, "dropped connection <%d.%d> to %s",
            this->serial, conn->serial, conn->peername);
  this->downstream = NULL;
  if (evbuffer_get_length(bufferevent_get_output(this->up_buffer)) > 0)
    /* this may already have happened, but there's no harm in
       doing it again */
    circuit_do_flush(this);
  else
    circuit_close(this);
}

/* Send data from the upstream buffer. */
int
null_circuit_t::send()
{
  return evbuffer_add_buffer(conn_get_outbound(this->downstream),
                             bufferevent_get_input(this->up_buffer));
}

/* Send an EOF on this circuit. */
int
null_circuit_t::send_eof()
{
  if (this->downstream)
    conn_send_eof(this->downstream);
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
  conn->cfg = this;
  return conn;
}

null_conn_t::null_conn_t()
{
}

null_conn_t::~null_conn_t()
{
}

/** Null inbound-to-outbound connections are 1:1 */
int
null_conn_t::maybe_open_upstream()
{
  circuit_t *ckt = circuit_create(this->cfg, 0);
  if (!ckt)
    return -1;

  circuit_add_downstream(ckt, this);
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
  log_assert(this->circuit);
  return evbuffer_add_buffer(bufferevent_get_output(this->circuit->up_buffer),
                             conn_get_inbound(this));
}

/** Receive EOF from connection SOURCE */
int
null_conn_t::recv_eof()
{
  if (this->circuit) {
    if (evbuffer_get_length(conn_get_inbound(this)) > 0)
      if (this->recv())
        return -1;

    circuit_recv_eof(this->circuit);
  }
  return 0;
}

CONN_STEG_STUBS(null);
