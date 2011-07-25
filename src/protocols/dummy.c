/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "../util.h"

#define PROTOCOL_DUMMY_PRIVATE
#include "dummy.h"

#include <event2/buffer.h>

/* type-safe downcast wrappers */
static inline dummy_params_t *
downcast_params(protocol_params_t *p)
{
  return DOWNCAST(dummy_params_t, super, p);
}

static inline dummy_protocol_t *
downcast_protocol(protocol_t *p)
{
  return DOWNCAST(dummy_protocol_t, super, p);
}

static int parse_and_set_options(int n_options,
                                 const char *const *options,
                                 dummy_params_t *params);

/**
   This function populates 'params' according to 'options' and sets up
   the protocol vtable.

   'options' is an array like this:
   {"dummy","socks","127.0.0.1:6666"}
*/
static protocol_params_t *
dummy_init(int n_options, const char *const *options)
{
  dummy_params_t *params = xzalloc(sizeof(dummy_params_t));
  params->super.vtable = &dummy_vtable;

  if (parse_and_set_options(n_options, options, params) == 0)
    return &params->super;

  proto_params_free(&params->super);
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
   Helper: Parses 'options' and fills 'params'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      dummy_params_t *params)
{
  const char* defport;

  if (n_options < 1)
    return -1;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    params->super.mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    params->super.mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    params->super.mode = LSN_SIMPLE_SERVER;
  } else
    return -1;

  if (n_options != (params->super.mode == LSN_SOCKS_CLIENT ? 2 : 3))
      return -1;

  params->super.listen_addr = resolve_address_port(options[1], 1, 1, defport);
  if (!params->super.listen_addr)
    return -1;

  if (params->super.mode != LSN_SOCKS_CLIENT) {
    params->super.target_addr = resolve_address_port(options[2], 1, 0, NULL);
    if (!params->super.target_addr)
      return -1;
  }

  return 0;
}

static void
dummy_fini(protocol_params_t *params)
{
  free(downcast_params(params));
}

/*
  This is called everytime we get a connection for the dummy
  protocol.
*/

static protocol_t *
dummy_create(protocol_params_t *params)
{
  dummy_protocol_t *proto = xzalloc(sizeof(dummy_protocol_t));
  proto->super.vtable = &dummy_vtable;
  return &proto->super;
}

static void
dummy_destroy(protocol_t *proto)
{
  free(downcast_protocol(proto));
}

/** Dummy has no handshake */
static int
dummy_handshake(protocol_t *proto, struct evbuffer *buf)
{
  return 0;
}

/** send, receive - just copy */
static int
dummy_send(protocol_t *proto, struct evbuffer *source, struct evbuffer *dest)
{
  return evbuffer_add_buffer(dest,source);
}

static enum recv_ret
dummy_recv(protocol_t *proto, struct evbuffer *source, struct evbuffer *dest)
{
  if (evbuffer_add_buffer(dest,source)<0)
    return RECV_BAD;
  else
    return RECV_GOOD;
}

DEFINE_PROTOCOL_VTABLE(dummy);
