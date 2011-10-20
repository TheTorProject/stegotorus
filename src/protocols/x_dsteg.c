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
  int received_fin;
  int sent_fin;
  int ever_transmitted;
  int ever_received;
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
x_dsteg_config_get_target_addrs(config_t *cfg, size_t n)
{
  if (n > 0)
    return 0;
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
  log_assert(!ckt->downstream);
  ckt->downstream = conn;
  log_debug_ckt(c, "added connection <%d.%d> to %s",
                c->serial, conn->serial, conn->peername);
  circuit_disarm_axe_timer(c);
}

/* Drop a connection from this circuit.  This may happen because of a
   network error or because the steg module wanted it to happen. */
static void
x_dsteg_circuit_drop_downstream(circuit_t *c, conn_t *conn)
{
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
  log_assert(ckt->downstream == conn);
  ckt->downstream = NULL;
  log_debug_ckt(c, "dropped connection <%d.%d> to %s",
                c->serial, conn->serial, conn->peername);
  if (ckt->sent_fin && ckt->received_fin) {
    if (evbuffer_get_length(bufferevent_get_output(c->up_buffer)) > 0)
      /* this may already have happened, but there's no harm in
         doing it again */
      circuit_do_flush(c);
    else
      circuit_close(c);
  } else
    circuit_arm_axe_timer(c, 100);
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

/** Dsteg has no handshake as such, but on the client side, we must
    send _something_ shortly after connection even if we have no data
    to pass along.  Otherwise, the server will never find out what
    steg target to use, and if it has something to say but we don't,
    it will never get a chance.  x_dsteg_transmit knows what to do
    when the flush timer goes off with no data to send.  */
static int
x_dsteg_conn_handshake(conn_t *conn)
{
  if (conn->cfg->mode != LSN_SIMPLE_SERVER)
    circuit_arm_flush_timer(conn->circuit, 1);
  return 0;
}

/*
  Dsteg packs a chunk of data and a chunk of chaff into a block with
  a 32-bit header and an 8-bit trailer:
  | DLen (uint16_t) | CLen (uint16_t) | DLen bytes data | CLen bytes chaff | F
  The F field is flags, of which only one is presently defined:
  0x01 - this is the last transmission in this direction for this circuit.
  (This disambiguates whether a connection close happens because the circuit
  is going away, or because the cover protocol requires it.)
*/
struct ds_wire_header {
  uint16_t dlen;
  uint16_t clen;
};

static struct evbuffer *
ds_pack(struct evbuffer *source, uint16_t dlen, uint16_t clen, int fin)
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

  if (evbuffer_reserve_space(block, clen + 1, &v, 1) != 1)
    goto fail;
  v.iov_len = clen + 1;

  if (random_bytes(v.iov_base, clen))
    goto fail;

  ((char *)v.iov_base)[clen] = fin ? 0x01 : 0x00;

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
ds_unpack(struct evbuffer *dest, struct evbuffer *source, int *fin)
{
  struct ds_wire_header hdr = { 0, 0 };
  uint8_t flags;

  if (evbuffer_remove(source, &hdr, sizeof hdr) != sizeof hdr)
    goto fail;

  hdr.dlen = ntohs(hdr.dlen);
  hdr.clen = ntohs(hdr.clen);

  if (hdr.dlen > 0)
    if (evbuffer_remove_buffer(source, dest, hdr.dlen) != hdr.dlen)
      goto fail;

  if (evbuffer_drain(source, hdr.clen))
    goto fail;

  if (evbuffer_remove(source, &flags, 1) != 1)
    goto fail;

  /* ignore unrecognized flag bits */
  *fin = !!(flags & 0x01);

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
  x_dsteg_conn_t *dest;
  steg_t *steg = NULL;
  size_t room;
  size_t avail = evbuffer_get_length(source);
  int rv = 0;
  int fin = ckt->sent_fin;

  circuit_disarm_flush_timer(c);

  if (!d) {
    log_debug("x_dsteg: no downstream connection");
    if (c->cfg->mode != LSN_SIMPLE_SERVER)
      circuit_reopen_downstreams(c);
    return 0;
  }

  dest = downcast_conn(d);
  steg = dest->steg;

  /* If we haven't detected a steg target yet, we can't transmit.
     This is not an error condition, we just have to wait for the
     client to say something. */
  if (!steg) {
    log_debug("x_dsteg: waiting for target detection");
    return 0;
  }

  /* Only transmit if we have room. */
  room = steg_transmit_room(steg, d);
  if (room > UINT16_MAX)
    room = UINT16_MAX;
  log_debug("x_dsteg: can transmit %lu bytes", (unsigned long)room);
  if (room) {
    /* If we are here with nothing to transmit, send chaff. */
    if (avail == 0) {
      room = random_int(room) + 1;
      block = ds_pack(source, 0, room, fin);
      if (!block)
        return -1;
      rv = steg_transmit(steg, block, d);
      evbuffer_free(block);
      if (rv < 0)
        return -1;
      log_debug("x_dsteg: %lu bytes chaff sent (%lu on wire)",
                (unsigned long) room,
                (unsigned long) evbuffer_get_length(conn_get_outbound(d)));
    } else {
      /* Don't send any more than we have. */
      if (room > avail)
        room = avail;
      /* If we can't send all of it, don't send a FIN. */
      if (room < avail)
        fin = 0;

      block = ds_pack(source, room, 0, fin);
      if (!block)
        return -1;
      rv = steg_transmit(steg, block, d);
      evbuffer_free(block);
      if (rv < 0)
        return -1;

      avail -= room;
      log_debug("x_dsteg: %lu bytes sent (%lu on wire)%s, %lu still pending",
                (unsigned long)room,
                (unsigned long)evbuffer_get_length(conn_get_outbound(d)),
                fin ? " [FIN]" : "",
                (unsigned long)avail);
    }
    ckt->ever_transmitted = 1;
  }

  /* If that was successful, but we still have data pending, receipt
     of a response will trigger another transmission.  But in case
     that doesn't happen set a timer to force more data out shortly. */
  if (avail)
    circuit_arm_flush_timer(c, 10);
  else if (fin)
    conn_send_eof(ckt->downstream);

  return 0;
}

/** send EOF: flush out any queued data if possible */
static int
x_dsteg_circuit_send_eof(circuit_t *c)
{
  x_dsteg_circuit_t *ckt = downcast_circuit(c);
  ckt->sent_fin = 1;
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
    } else {
      conn_send_eof(ckt->downstream);
    }
  }
  return 0;
}


/* Receive data from S. */
static int
x_dsteg_conn_recv(conn_t *s)
{
  x_dsteg_conn_t *source = downcast_conn(s);
  struct evbuffer *block, *dest;
  size_t in, out;
  int fin = 0;

  if (!source->steg) {
    log_assert(s->cfg->mode == LSN_SIMPLE_SERVER);
    if (evbuffer_get_length(conn_get_inbound(s)) == 0)
      return 0; /* need more data */
    source->steg = steg_detect(s);
    if (!source->steg) {
      log_debug("No recognized steg pattern detected");
      return -1;
    } else {
      log_debug("Detected steg pattern %s", source->steg->vtable->name);
    }
  }
  in = evbuffer_get_length(conn_get_inbound(s));
  block = evbuffer_new();
  if (!block)
    return -1;
  if (steg_receive(source->steg, s, block)) {
    evbuffer_free(block);
    return -1;
  }

  dest = bufferevent_get_output(s->circuit->up_buffer);
  while (evbuffer_get_length(block) > 0) {
    if (ds_unpack(dest, block, &fin)) {
      evbuffer_free(block);
      return -1;
    }
    log_assert(!fin || evbuffer_get_length(block) == 0);
  }
  evbuffer_free(block);

  downcast_circuit(s->circuit)->ever_received = 1;
  if (fin)
    downcast_circuit(s->circuit)->received_fin = 1;

  in -= evbuffer_get_length(conn_get_inbound(s));
  out = evbuffer_get_length(dest);
  log_debug("x_dsteg: received %lu bytes (%lu on wire)%s",
            (unsigned long)out, (unsigned long)in, fin ? " [FIN]" : "");

  /* check for pending transmissions */
  in = evbuffer_get_length(bufferevent_get_input(s->circuit->up_buffer));
  if (in == 0)
    return 0;

  log_debug("x_dsteg: %lu bytes waiting to be sent", (unsigned long)in);
  return x_dsteg_circuit_send(s->circuit);
}


/** Receive EOF from connection SOURCE */
static int
x_dsteg_conn_recv_eof(conn_t *source)
{
  if (source->circuit) {
    if (evbuffer_get_length(conn_get_inbound(source)) > 0)
      if (x_dsteg_conn_recv(source))
        return -1;

    if (downcast_circuit(source->circuit)->received_fin)
      circuit_recv_eof(source->circuit);
  }
  return 0;
}

static void x_dsteg_conn_expect_close(conn_t *conn)
{
  /* do we need to do something here? */
}

static void x_dsteg_conn_cease_transmission(conn_t *conn)
{
  conn_do_flush(conn);  /*???*/
}

static void x_dsteg_conn_close_after_transmit(conn_t *conn)
{
  conn_do_flush(conn);
}

static void x_dsteg_conn_transmit_soon(conn_t *conn, unsigned long timeout)
{
  circuit_arm_flush_timer(conn->circuit, timeout);
}
