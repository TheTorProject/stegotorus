/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "../util.h"

#include "dummy.h"
#include "../protocol.h"

#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>

static void usage(void);
static int parse_and_set_options(int n_options,
                                 const char *const *options,
                                 struct protocol_params_t *params);

/**
   This function populates 'params' according to 'options' and sets up
   the protocol vtable.

   'options' is an array like this:
   {"dummy","socks","127.0.0.1:6666"}
*/
static struct protocol_params_t *
dummy_init(int n_options, const char *const *options)
{
  struct protocol_params_t *params
    = xzalloc(sizeof(struct protocol_params_t));
  params->vtable = &dummy_vtable;

  if (parse_and_set_options(n_options, options, params) < 0) {
    proto_params_free(params);
    usage();
    return NULL;
  }

  return params;
}

/**
   Helper: Parses 'options' and fills 'params'.
*/
static int
parse_and_set_options(int n_options, const char *const *options,
                      struct protocol_params_t *params)
{
  const char* defport;

  if (n_options < 1)
    return -1;

  if (!strcmp(options[0], "client")) {
    defport = "48988"; /* bf5c */
    params->mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; /* 5bf5 */
    params->mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    params->mode = LSN_SIMPLE_SERVER;
  } else
    return -1;

  if (n_options != (params->mode == LSN_SOCKS_CLIENT ? 2 : 3))
      return -1;

  params->listen_addr = resolve_address_port(options[1], 1, 1, defport);
  if (!params->listen_addr)
    return -1;

  if (params->mode != LSN_SOCKS_CLIENT) {
    params->target_addr = resolve_address_port(options[2], 1, 0, NULL);
    if (!params->target_addr)
      return -1;
  }

  params->vtable = &dummy_vtable;
  return 0;
}

/**
   Prints dummy protocol usage information.
*/
static void
usage(void)
{
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
}

static void
dummy_fini(struct protocol_params_t *params)
{
  free(params);
}

/*
  This is called everytime we get a connection for the dummy
  protocol.
*/

static struct protocol_t *
dummy_create(struct protocol_params_t *params)
{
  /* Dummy needs no per-connection protocol-specific state. */
  struct protocol_t *proto = xzalloc(sizeof(struct protocol_t));
  proto->vtable = &dummy_vtable;
  return proto;
}

static void
dummy_destroy(struct protocol_t *proto)
{
  free(proto);
}

/**
   Responsible for sending data according to the dummy protocol.

   The dummy protocol just puts the data of 'source' in 'dest'.
*/
static int
dummy_handshake(struct protocol_t *proto, struct evbuffer *buf)
{
  return 0;
}

static int
dummy_send(struct protocol_t *proto,
           struct evbuffer *source, struct evbuffer *dest)
{
  return evbuffer_add_buffer(dest,source);
}

/*
  Responsible for receiving data according to the dummy protocol.

  The dummy protocol just puts the data of 'source' into 'dest'.
*/
static enum recv_ret
dummy_recv(struct protocol_t *proto,
           struct evbuffer *source, struct evbuffer *dest)
{
  if (evbuffer_add_buffer(dest,source)<0)
    return RECV_BAD;
  else
    return RECV_GOOD;
}

DEFINE_PROTOCOL_VTABLE(dummy);
