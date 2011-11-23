/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"

#include <event2/buffer.h>

typedef struct x_null_config_t {
  config_t super;
  struct evutil_addrinfo *listen_addr;
  struct evutil_addrinfo *target_addr;
} x_null_config_t;

typedef struct x_null_conn_t {
  conn_t super;
} x_null_conn_t;

typedef struct x_null_circuit_t {
  circuit_t super;
  conn_t *downstream;
} x_null_circuit_t;

PROTO_DEFINE_MODULE(x_null, NOSTEG);

/**
   Helper: Parses 'options' and fills 'cfg'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      config_t *c)
{
  const char* defport;
  x_null_config_t *cfg = downcast_config(c);

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
x_null_config_free(config_t *c)
{
  x_null_config_t *cfg = downcast_config(c);
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
x_null_config_create(int n_options, const char *const *options)
{
  x_null_config_t *cfg = (x_null_config_t *)xzalloc(sizeof(x_null_config_t));
  config_t *c = upcast_config(cfg);
  c->vtable = &p_x_null_vtable;

  if (parse_and_set_options(n_options, options, c) == 0)
    return c;

  x_null_config_free(c);
  log_warn("x_null syntax:\n"
           "\tx_null <mode> <listen_address> [<target_address>]\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tlisten_address, target_address ~ host:port\n"
           "\ttarget_address is required for server and client mode,\n"
           "\tand forbidden for socks mode.\n"
           "Examples:\n"
           "\tstegotorus x_null socks 127.0.0.1:5000\n"
           "\tstegotorus x_null client 127.0.0.1:5000 192.168.1.99:11253\n"
           "\tstegotorus x_null server 192.168.1.99:11253 127.0.0.1:9005");
  return NULL;
}

/** Retrieve the 'n'th set of listen addresses for this configuration. */
static struct evutil_addrinfo *
x_null_config_get_listen_addrs(config_t *cfg, size_t n)
{
  if (n > 0)
    return 0;
  return downcast_config(cfg)->listen_addr;
}

/* Retrieve the target address for this configuration. */
static struct evutil_addrinfo *
x_null_config_get_target_addrs(config_t *cfg, size_t n)
{
  if (n > 0)
    return 0;
  return downcast_config(cfg)->target_addr;
}

/* Create a circuit object. */
static circuit_t *
x_null_circuit_create(config_t *c)
{
  circuit_t *ckt = upcast_circuit((x_null_circuit_t *)
                                  xzalloc(sizeof(x_null_circuit_t)));
  ckt->cfg = c;
  return ckt;
}

/* Destroy a circuit object. */
static void
x_null_circuit_free(circuit_t *c)
{
  x_null_circuit_t *ckt = downcast_circuit(c);
  if (ckt->downstream) {
    /* break the circular reference before deallocating the
       downstream connection */
    ckt->downstream->circuit = NULL;
    conn_close(ckt->downstream);
  }

  free(ckt);
}

/* Add a connection to this circuit. */
static void
x_null_circuit_add_downstream(circuit_t *c, conn_t *conn)
{
  x_null_circuit_t *ckt = downcast_circuit(c);
  log_assert(!ckt->downstream);
  ckt->downstream = conn;
  log_debug(c, "added connection <%d.%d> to %s",
            c->serial, conn->serial, conn->peername);
}

/* Drop a connection from this circuit.  If this happens in this
   protocol, it is because of a network error, and the whole circuit
   should be closed.  */
static void
x_null_circuit_drop_downstream(circuit_t *c, conn_t *conn)
{
  x_null_circuit_t *ckt = downcast_circuit(c);
  log_assert(ckt->downstream == conn);
  log_debug(c, "dropped connection <%d.%d> to %s",
            c->serial, conn->serial, conn->peername);
  ckt->downstream = NULL;
  if (evbuffer_get_length(bufferevent_get_output(c->up_buffer)) > 0)
    /* this may already have happened, but there's no harm in
       doing it again */
    circuit_do_flush(c);
  else
    circuit_close(c);
}

/* Send data from circuit C. */
static int
x_null_circuit_send(circuit_t *c)
{
  x_null_circuit_t *ckt = downcast_circuit(c);
  return evbuffer_add_buffer(conn_get_outbound(ckt->downstream),
                             bufferevent_get_input(c->up_buffer));
}

/* Send an EOF on circuit C. */
static int
x_null_circuit_send_eof(circuit_t *c)
{
  x_null_circuit_t *ckt = downcast_circuit(c);
  if (ckt->downstream)
    conn_send_eof(ckt->downstream);
  return 0;
}

/*
  This is called everytime we get a connection for the x_null
  protocol.
*/

static conn_t *
x_null_conn_create(config_t *cfg)
{
  x_null_conn_t *conn = (x_null_conn_t *)xzalloc(sizeof(x_null_conn_t));
  conn_t *c = upcast_conn(conn);
  c->cfg = cfg;
  return c;
}

static void
x_null_conn_free(conn_t *c)
{
  free(downcast_conn(c));
}

/** Null inbound-to-outbound connections are 1:1 */
static int
x_null_conn_maybe_open_upstream(conn_t *conn)
{
  circuit_t *ckt = circuit_create(conn->cfg);
  if (!ckt)
    return -1;

  circuit_add_downstream(ckt, conn);
  circuit_open_upstream(ckt);
  return 0;
}

/** Null has no handshake */
static int
x_null_conn_handshake(conn_t *c)
{
  return 0;
}

/** Receive data from connection SOURCE */
static int
x_null_conn_recv(conn_t *source)
{
  log_assert(source->circuit);
  return evbuffer_add_buffer(bufferevent_get_output(source->circuit->up_buffer),
                             conn_get_inbound(source));
}

/** Receive EOF from connection SOURCE */
static int
x_null_conn_recv_eof(conn_t *source)
{
  if (source->circuit) {
    if (evbuffer_get_length(conn_get_inbound(source)) > 0)
      if (x_null_conn_recv(source))
        return -1;

    circuit_recv_eof(source->circuit);
  }
  return 0;
}
