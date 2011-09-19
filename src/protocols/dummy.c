/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"

#include <event2/buffer.h>

typedef struct dummy_config_t {
  config_t super;
  struct evutil_addrinfo *listen_addr;
  struct evutil_addrinfo *target_addr;
} dummy_config_t;

typedef struct dummy_conn_t {
  conn_t super;
} dummy_conn_t;

typedef struct dummy_circuit_t {
  circuit_t super;
} dummy_circuit_t;

PROTO_DEFINE_MODULE(dummy, NOSTEG);

/**
   Helper: Parses 'options' and fills 'cfg'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      config_t *c)
{
  const char* defport;
  dummy_config_t *cfg = downcast_config(c);

  if (n_options < 1)
    return -1;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    c->mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    c->mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    c->mode = LSN_SIMPLE_SERVER;
  } else
    return -1;

  if (n_options != (c->mode == LSN_SOCKS_CLIENT ? 2 : 3))
      return -1;

  cfg->listen_addr = resolve_address_port(options[1], 1, 1, defport);
  if (!cfg->listen_addr)
    return -1;

  if (c->mode != LSN_SOCKS_CLIENT) {
    cfg->target_addr = resolve_address_port(options[2], 1, 0, NULL);
    if (!cfg->target_addr)
      return -1;
  }

  return 0;
}

/* Deallocate 'cfg'. */
static void
dummy_config_free(config_t *c)
{
  dummy_config_t *cfg = downcast_config(c);
  if (cfg->listen_addr)
    evutil_freeaddrinfo(cfg->listen_addr);
  if (cfg->target_addr)
    evutil_freeaddrinfo(cfg->target_addr);
  free(cfg);
}

/**
   Populate 'cfg' according to 'options', which is an array like this:
   {"socks","127.0.0.1:6666"}
*/
static config_t *
dummy_config_create(int n_options, const char *const *options)
{
  dummy_config_t *cfg = xzalloc(sizeof(dummy_config_t));
  config_t *c = upcast_config(cfg);
  c->vtable = &p_dummy_vtable;

  if (parse_and_set_options(n_options, options, c) == 0)
    return c;

  dummy_config_free(c);
  log_warn("dummy syntax:\n"
           "\tdummy <mode> <listen_address> [<target_address>]\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tlisten_address, target_address ~ host:port\n"
           "\ttarget_address is required for server and client mode,\n"
           "\tand forbidden for socks mode.\n"
           "Examples:\n"
           "\tobfsproxy dummy socks 127.0.0.1:5000\n"
           "\tobfsproxy dummy client 127.0.0.1:5000 192.168.1.99:11253\n"
           "\tobfsproxy dummy server 192.168.1.99:11253 127.0.0.1:9005");
  return NULL;
}

/** Retrieve the 'n'th set of listen addresses for this configuration. */
static struct evutil_addrinfo *
dummy_config_get_listen_addrs(config_t *cfg, size_t n)
{
  if (n > 0)
    return 0;
  return downcast_config(cfg)->listen_addr;
}

/* Retrieve the target address for this configuration. */
static struct evutil_addrinfo *
dummy_config_get_target_addr(config_t *cfg)
{
  return downcast_config(cfg)->target_addr;
}

/* Create a circuit object. */
static circuit_t *
dummy_circuit_create(config_t *c)
{
  circuit_t *ckt = upcast_circuit(xzalloc(sizeof(dummy_circuit_t)));
  ckt->cfg = c;
  return ckt;
}

/* Destroy a circuit object. */
static void
dummy_circuit_free(circuit_t *c)
{
  free(downcast_circuit(c));
}

/* Add a connection to this circuit. */
static void
dummy_circuit_add_downstream(circuit_t *ckt, conn_t *conn)
{
  obfs_assert(!ckt->downstream);
  ckt->downstream = conn;
}

/* Send data from circuit C. */
static int
dummy_circuit_send(circuit_t *c)
{
  return evbuffer_add_buffer(conn_get_outbound(c->downstream),
                             bufferevent_get_input(c->up_buffer));
}

/*
  This is called everytime we get a connection for the dummy
  protocol.
*/

static conn_t *
dummy_conn_create(config_t *cfg)
{
  dummy_conn_t *conn = xzalloc(sizeof(dummy_conn_t));
  conn_t *c = upcast_conn(conn);
  c->cfg = cfg;
  return c;
}

static void
dummy_conn_free(conn_t *c)
{
  free(downcast_conn(c));
}

/** Dummy inbound-to-outbound connections are 1:1 */
static int
dummy_conn_maybe_open_upstream(conn_t *conn)
{
  circuit_t *ckt = circuit_create(conn->cfg);
  if (!ckt)
    return -1;

  circuit_add_downstream(ckt, conn);
  circuit_open_upstream(ckt);
  return 0;
}

/** Dummy has no handshake */
static int
dummy_conn_handshake(conn_t *c)
{
  return 0;
}

/** Receive data from connection SOURCE */
static enum recv_ret
dummy_conn_recv(conn_t *source)
{
  obfs_assert(source->circuit);
  if (evbuffer_add_buffer(bufferevent_get_output(source->circuit->up_buffer),
                          conn_get_inbound(source)))
    return RECV_BAD;
  else
    return RECV_GOOD;
}

/** send EOF, recv EOF - no op */
static int
dummy_conn_send_eof(conn_t *dest)
{
  return 0;
}

static enum recv_ret
dummy_conn_recv_eof(conn_t *source)
{
  return RECV_GOOD;
}
