/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"

#define PROTOCOL_X_DSTEG_PRIVATE
#include "x_dsteg.h"

#include <event2/buffer.h>

PROTO_DEFINE_MODULE(x_dsteg, STEG);

/**
   Helper: Parses 'options' and fills 'cfg'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      config_t *c)
{
  const char* defport;
  int req_options;
  x_dsteg_config_t *cfg = downcast_config(c);

  if (n_options < 1)
    return -1;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    c->mode = LSN_SIMPLE_CLIENT;
    req_options = 4;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    c->mode = LSN_SOCKS_CLIENT;
    req_options = 3;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    c->mode = LSN_SIMPLE_SERVER;
    req_options = 3;
  } else
    return -1;

  if (n_options != req_options)
      return -1;

  cfg->listen_addr = resolve_address_port(options[1], 1, 1, defport);
  if (!cfg->listen_addr)
    return -1;

  if (c->mode != LSN_SOCKS_CLIENT) {
    cfg->target_addr = resolve_address_port(options[2], 1, 0, NULL);
    if (!cfg->target_addr)
      return -1;
  }

  if (c->mode != LSN_SIMPLE_SERVER) {
    cfg->stegname = options[c->mode == LSN_SOCKS_CLIENT ? 2 : 3];
    if (!steg_is_supported(cfg->stegname))
      return -1;
  }

  return 0;
}

/* Deallocate 'cfg'. */
static void
x_dsteg_config_free(config_t *c)
{
  x_dsteg_config_t *cfg = downcast_config(c);
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
x_dsteg_config_create(int n_options, const char *const *options)
{
  x_dsteg_config_t *cfg = xzalloc(sizeof(x_dsteg_config_t));
  config_t *c = upcast_config(cfg);
  c->vtable = &p_x_dsteg_vtable;

  if (parse_and_set_options(n_options, options, c) == 0)
    return c;

  x_dsteg_config_free(c);
  log_warn("x_dsteg syntax:\n"
           "\tx_dsteg <mode> <listen_address> [<target_address>] [<steg>]\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tlisten_address, target_address ~ host:port\n"
           "\t\tsteg ~ steganography module name\n"
           "\ttarget_address is required for server and client mode,\n"
           "\tand forbidden for socks mode.\n"
           "\tsteg is required for client and socks mode,\n"
           "\tforbidden for server.\n"
           "Examples:\n"
           "\tobfsproxy x_dsteg socks 127.0.0.1:5000 x_http\n"
           "\tobfsproxy x_dsteg client 127.0.0.1:5000 192.168.1.99:11253 x_http\n"
           "\tobfsproxy x_dsteg server 192.168.1.99:11253 127.0.0.1:9005");
  return NULL;
}

/** Retrieve the 'n'th set of listen addresses for this configuration. */
static struct evutil_addrinfo *
x_dsteg_config_get_listen_addrs(config_t *cfg, size_t n)
{
  if (n > 0)
    return 0;
  return downcast_config(cfg)->listen_addr;
}

/* Retrieve the target address for this configuration. */
static struct evutil_addrinfo *
x_dsteg_config_get_target_addr(config_t *cfg)
{
  return downcast_config(cfg)->target_addr;
}

/* Create a circuit object. */
static circuit_t *
x_dsteg_circuit_create(config_t *c)
{
  circuit_t *ckt = upcast_circuit(xzalloc(sizeof(x_dsteg_circuit_t)));
  ckt->cfg = c;
  return ckt;
}

/* Destroy a circuit object. */
static void
x_dsteg_circuit_free(circuit_t *c)
{
  free(downcast_circuit(c));
}

/* Add a connection to this circuit. */
static void
x_dsteg_circuit_add_downstream(circuit_t *ckt, conn_t *conn)
{
  obfs_assert(!ckt->downstream);
  ckt->downstream = conn;
}

/*
  This is called everytime we get a connection for the x_dsteg
  protocol.
*/

static conn_t *
x_dsteg_conn_create(config_t *c)
{
  x_dsteg_config_t *cfg = downcast_config(c);
  x_dsteg_conn_t *conn = xzalloc(sizeof(x_dsteg_conn_t));
  conn_t *cn = upcast_conn(conn);

  cn->cfg = c;
  if (c->mode != LSN_SIMPLE_SERVER) {
    conn->steg = steg_new(cfg->stegname);
    if (!conn->steg) {
      free(conn);
      return 0;
    }
  }
  return cn;
}

static void
x_dsteg_conn_free(conn_t *c)
{
  x_dsteg_conn_t *conn = downcast_conn(c);
  if (conn->steg)
    steg_del(conn->steg);
  free(conn);
}

/** FIXME: Whether or not inbound-to-outbound connections are 1:1
    depends on the steg module we're wrapping.  Treat it as always so
    for now.  */
static int
x_dsteg_conn_maybe_open_upstream(conn_t *conn)
{
  circuit_t *ckt = circuit_create(conn->cfg);
  if (!ckt)
    return -1;

  circuit_add_downstream(ckt, conn);
  circuit_open_upstream(ckt);
  return 0;
}

/** Dsteg has no handshake */
static int
x_dsteg_conn_handshake(conn_t *conn)
{
  return 0;
}

static int
x_dsteg_circuit_send(circuit_t *c)
{
  conn_t *d = c->downstream;
  struct evbuffer *source = bufferevent_get_input(c->up_buffer);
  struct evbuffer *chunk = evbuffer_new();
  x_dsteg_conn_t *dest = downcast_conn(d);
  steg_t *steg = dest->steg;

  obfs_assert(steg);
  if (evbuffer_remove_buffer(source, chunk, steg_transmit_room(steg, d)) < 0) {
    evbuffer_free(chunk);
    return -1;
  }
  if (steg_transmit(steg, chunk, d)) {
    /* undo undo undo */
    evbuffer_prepend_buffer(source, chunk);
    evbuffer_free(chunk);
    return -1;
  }
  return 0;
}

/* Receive data from S. */
static enum recv_ret
x_dsteg_conn_recv(conn_t *s)
{
  x_dsteg_conn_t *source = downcast_conn(s);
  if (!source->steg) {
    obfs_assert(s->cfg->mode == LSN_SIMPLE_SERVER);
    if (evbuffer_get_length(conn_get_inbound(s)) == 0)
      return RECV_INCOMPLETE;
    source->steg = steg_detect(s);
    if (!source->steg) {
      log_debug("No recognized steg pattern detected");
      return RECV_BAD;
    } else {
      log_debug("Detected steg pattern %s", source->steg->vtable->name);
    }
  }
  return steg_receive(source->steg, s,
                      bufferevent_get_output(s->circuit->up_buffer));
}


/** send EOF, recv EOF - no op */
static int
x_dsteg_conn_send_eof(conn_t *dest)
{
  return 0;
}

static enum recv_ret
x_dsteg_conn_recv_eof(conn_t *source)
{
  return RECV_GOOD;
}


/** XXX all steg callbacks are ignored */
static void x_dsteg_conn_expect_close(conn_t *conn) {}
static void x_dsteg_conn_cease_transmission(conn_t *conn) {}
static void x_dsteg_conn_close_after_transmit(conn_t *conn) {}
static void x_dsteg_conn_transmit_soon(conn_t *conn, unsigned long timeout) {}
