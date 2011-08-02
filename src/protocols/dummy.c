/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "../util.h"

#define PROTOCOL_DUMMY_PRIVATE
#include "dummy.h"

#include <event2/buffer.h>

/* type-safe downcast wrappers */
static inline dummy_listener_t *
downcast_listener(listener_t *p)
{
  return DOWNCAST(dummy_listener_t, super, p);
}

static inline dummy_conn_t *
downcast_conn(conn_t *p)
{
  return DOWNCAST(dummy_conn_t, super, p);
}

static int parse_and_set_options(int n_options,
                                 const char *const *options,
                                 dummy_listener_t *lsn);

/**
   This function populates 'lsn' according to 'options' and sets up
   the protocol vtable.

   'options' is an array like this:
   {"dummy","socks","127.0.0.1:6666"}
*/
static listener_t *
dummy_listener_create(int n_options, const char *const *options)
{
  dummy_listener_t *lsn = xzalloc(sizeof(dummy_listener_t));
  lsn->super.vtable = &dummy_vtable;

  if (parse_and_set_options(n_options, options, lsn) == 0)
    return &lsn->super;

  if (lsn->super.listen_addr)
    evutil_freeaddrinfo(lsn->super.listen_addr);
  if (lsn->super.target_addr)
    evutil_freeaddrinfo(lsn->super.target_addr);
  free(lsn);

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

/**
   Helper: Parses 'options' and fills 'lsn'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      dummy_listener_t *lsn)
{
  const char* defport;

  if (n_options < 1)
    return -1;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    lsn->super.mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    lsn->super.mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    lsn->super.mode = LSN_SIMPLE_SERVER;
  } else
    return -1;

  if (n_options != (lsn->super.mode == LSN_SOCKS_CLIENT ? 2 : 3))
      return -1;

  lsn->super.listen_addr = resolve_address_port(options[1], 1, 1, defport);
  if (!lsn->super.listen_addr)
    return -1;

  if (lsn->super.mode != LSN_SOCKS_CLIENT) {
    lsn->super.target_addr = resolve_address_port(options[2], 1, 0, NULL);
    if (!lsn->super.target_addr)
      return -1;
  }

  return 0;
}

static void
dummy_listener_free(listener_t *lsn)
{
  free(downcast_listener(lsn));
}

/*
  This is called everytime we get a connection for the dummy
  protocol.
*/

static conn_t *
dummy_conn_create(listener_t *lsn)
{
  dummy_conn_t *proto = xzalloc(sizeof(dummy_conn_t));
  proto->super.vtable = &dummy_vtable;
  return &proto->super;
}

static void
dummy_conn_free(conn_t *proto)
{
  free(downcast_conn(proto));
}

/** Dummy has no handshake */
static int
dummy_handshake(conn_t *proto, struct evbuffer *buf)
{
  return 0;
}

/** send, receive - just copy */
static int
dummy_send(conn_t *proto, struct evbuffer *source, struct evbuffer *dest)
{
  return evbuffer_add_buffer(dest,source);
}

static enum recv_ret
dummy_recv(conn_t *proto, struct evbuffer *source, struct evbuffer *dest)
{
  if (evbuffer_add_buffer(dest,source)<0)
    return RECV_BAD;
  else
    return RECV_GOOD;
}

DEFINE_PROTOCOL_VTABLE(dummy);
