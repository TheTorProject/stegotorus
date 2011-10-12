/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include "crypt.h"

#include <event2/buffer.h>
#include <arpa/inet.h>

typedef struct x_dsteg_config_t {
  config_t super;
  struct evutil_addrinfo *listen_addr;
  struct evutil_addrinfo *target_addr;
  const char *stegname;
} x_dsteg_config_t;

typedef struct x_dsteg_conn_t {
  conn_t super;
  steg_t *steg;
} x_dsteg_conn_t;

typedef struct x_dsteg_circuit_t {
  circuit_t super;
  conn_t *downstream;
  int pending_eof;
  int ever_transmitted;
} x_dsteg_circuit_t;

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
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
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
x_dsteg_circuit_add_downstream(circuit_t *c, conn_t *conn)
{
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
  obfs_assert(!ckt->downstream);
  ckt->downstream = conn;
  /* On the client side, we must send _something_ shortly after
     connection even if we have no data to pass along, to inform the
     server what steg target it should use. */
  if (c->cfg->mode != LSN_SIMPLE_SERVER)
    circuit_arm_flush_timer(c, 10);
}

/* Drop a connection from this circuit.  If this happens in this
   protocol (at present - this will change when the steg callbacks get
   implemented) it is because of a network error, and the whole
   circuit should be closed.  */
static void
x_dsteg_circuit_drop_downstream(circuit_t *c, conn_t *conn)
{
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
  obfs_assert(ckt->downstream == conn);
  ckt->downstream = NULL;
  circuit_close(c);
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

/*
  Dsteg packs a chunk of data and a chunk of chaff into a block with
  a 32-bit header:
  | DLen (uint16_t) | CLen (uint16_t) | DLen bytes data | CLen bytes chaff |
*/
struct ds_wire_header {
  uint16_t dlen;
  uint16_t clen;
};

static struct evbuffer *
ds_pack(struct evbuffer *source, uint16_t dlen, uint16_t clen)
{
  struct ds_wire_header hdr;
  struct evbuffer_iovec v;
  struct evbuffer *block = evbuffer_new();

  if (!block)
    return NULL;

  hdr.dlen = htons(dlen);
  hdr.clen = htons(clen);
  if (evbuffer_add(block, &hdr, sizeof hdr))
    goto fail;

  if (dlen > 0)
    if (evbuffer_remove_buffer(source, block, dlen) != dlen)
      goto fail;

  if (evbuffer_reserve_space(block, clen, &v, 1) != 1)
    goto fail;
  v.iov_len = clen;

  if (random_bytes(v.iov_base, v.iov_len))
    goto fail;

  if (evbuffer_commit_space(block, &v, 1))
    goto fail;

  log_debug("x_dsteg: packed block of %hu/%hu bytes", dlen, clen);
  return block;

 fail:
  log_debug("x_dsteg: failed to pack block of %hu/%hu bytes", dlen, clen);
  evbuffer_free(block);
  return NULL;
}

static int
ds_unpack(struct evbuffer *dest, struct evbuffer *source)
{
  struct ds_wire_header hdr = { 0, 0 };
  if (evbuffer_remove(source, &hdr, sizeof hdr) != sizeof hdr)
    goto fail;

  hdr.dlen = ntohs(hdr.dlen);
  hdr.clen = ntohs(hdr.clen);

  if (hdr.dlen > 0)
    if (evbuffer_remove_buffer(source, dest, hdr.dlen) != hdr.dlen)
      goto fail;

  if (hdr.clen > 0)
    if (evbuffer_drain(source, hdr.clen))
      goto fail;

  log_debug("x_dsteg: unpacked block of %hu/%hu bytes", hdr.dlen, hdr.clen);
  return 0;

 fail:
  log_debug("x_dsteg: failed to unpack block of %hu/%hu bytes",
            hdr.dlen, hdr.clen);
  return -1;
}

static int
x_dsteg_circuit_send(circuit_t *c)
{
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
  conn_t *d = ckt->downstream;
  struct evbuffer *source = bufferevent_get_input(c->up_buffer);
  struct evbuffer *block;
  x_dsteg_conn_t *dest = downcast_conn(d);
  steg_t *steg = dest->steg;
  size_t room;
  int rv = 0;

  circuit_disarm_flush_timer(c);

  /* If we are here with nothing to transmit, it is because we need
     to transmit chaff so the server knows what steg target to use. */
  if (evbuffer_get_length(source) == 0) {
    obfs_assert(steg);
    room = random_int(steg_transmit_room(steg, d)) + 1;
    block = ds_pack(source, 0, room);
    rv = steg_transmit(steg, block, d);
    evbuffer_free(block);
    if (rv < 0)
      return -1;
    log_debug("x_dsteg: %lu bytes chaff sent (%lu on wire)",
              (unsigned long) room,
              (unsigned long) evbuffer_get_length(conn_get_outbound(d)));
    ckt->ever_transmitted = 1;
    return 0;
  }

  /* If we haven't detected a steg target yet, we can't transmit.
     This is not an error condition, we just have to wait for the
     client to say something. */
  if (!steg) {
    log_debug("x_dsteg: waiting for target detection");
    return 0;
  }

  /* Only transmit if we have room. */
  room = steg_transmit_room(steg, d);
  log_debug("x_dsteg: can transmit %lu bytes", (unsigned long)room);
  if (room) {
    if (room > UINT16_MAX)
      room = UINT16_MAX;
    if (room > evbuffer_get_length(source))
      room = evbuffer_get_length(source);

    block = ds_pack(source, room, 0);
    if (!block) return -1;
    rv = steg_transmit(steg, block, d);
    evbuffer_free(block);
    if (rv < 0)
      return -1;
    ckt->ever_transmitted = 1;
  }

  log_debug("x_dsteg: %lu bytes sent (%lu on wire), %lu still pending",
            (unsigned long)room,
            (unsigned long)evbuffer_get_length(conn_get_outbound(d)),
            (unsigned long)evbuffer_get_length(source));

  /* If that was successful, but we still have data pending, receipt
     of a response will trigger another transmission.  But in case
     that doesn't happen set a timer to force more data out shortly. */
  if (evbuffer_get_length(source) > 0)
    circuit_arm_flush_timer(c, 10);
  else if (ckt->pending_eof)
    conn_send_eof(ckt->downstream);

  return 0;
}

/** send EOF: flush out any queued data if possible */
static int
x_dsteg_circuit_send_eof(circuit_t *c)
{
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
  if (ckt->downstream) {
    struct evbuffer *source = bufferevent_get_input(c->up_buffer);
    size_t avail = evbuffer_get_length(source);
    log_debug("x_dsteg: %lu bytes to send at EOF", (unsigned long)avail);

    /* If we have never transmitted anything and we're the client,
       we should transmit chaff now; otherwise the server might never
       find out what steg target it should be using to send to us. */
    if (avail > 0 ||
        (!ckt->ever_transmitted && c->cfg->mode != LSN_SIMPLE_SERVER))
      if (x_dsteg_circuit_send(c))
        return -1;

    /* That might not have transmitted everything.  If so, the flush
       timer is active and we'll come back to circuit_send in due course. */
    avail = evbuffer_get_length(source);
    if (avail > 0) {
      log_debug("x_dsteg: %lu bytes still pending", (unsigned long)avail);
      ckt->pending_eof = 1;
    } else {
      conn_send_eof(ckt->downstream);
    }
  }
  return 0;
}


/* Receive data from S. */
static enum recv_ret
x_dsteg_conn_recv(conn_t *s)
{
  x_dsteg_conn_t *source = downcast_conn(s);
  struct evbuffer *block, *dest;
  enum recv_ret ret;
  size_t in, out;

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
  in = evbuffer_get_length(conn_get_inbound(s));
  block = evbuffer_new();
  if (!block)
    return RECV_BAD;
  ret = steg_receive(source->steg, s, block);
  if (ret != RECV_GOOD) {
    evbuffer_free(block);
    return ret;
  }

  dest = bufferevent_get_output(s->circuit->up_buffer);
  do {
    if (ds_unpack(dest, block)) {
      evbuffer_free(block);
      return RECV_BAD;
    }
  } while (evbuffer_get_length(block) > 0);
  evbuffer_free(block);

  in -= evbuffer_get_length(conn_get_inbound(s));
  out = evbuffer_get_length(dest);
  log_debug("x_dsteg: received %lu bytes (%lu on wire)",
            (unsigned long)out, (unsigned long)in);

  /* check for pending transmissions */
  in = evbuffer_get_length(bufferevent_get_input(s->circuit->up_buffer));
  if (in == 0)
    return RECV_GOOD;

  log_debug("x_dsteg: %lu bytes waiting to be sent", (unsigned long)in);
  return x_dsteg_circuit_send(s->circuit) ? RECV_BAD : RECV_GOOD;
}


/** Receive EOF from connection SOURCE */
static enum recv_ret
x_dsteg_conn_recv_eof(conn_t *source)
{
  if (source->circuit) {
    if (evbuffer_get_length(conn_get_inbound(source)) > 0)
      if (x_dsteg_conn_recv(source) == RECV_BAD)
        return RECV_BAD;

    circuit_recv_eof(source->circuit);
  }
  return RECV_GOOD;
}

/** XXX all steg callbacks are ignored */
static void x_dsteg_conn_expect_close(conn_t *conn) {}
static void x_dsteg_conn_cease_transmission(conn_t *conn) {}
static void x_dsteg_conn_close_after_transmit(conn_t *conn) {}
static void x_dsteg_conn_transmit_soon(conn_t *conn, unsigned long timeout) {}
