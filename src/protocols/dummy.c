/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>

#include <openssl/rand.h>
#include <event2/buffer.h>

#include "dummy.h"
#include "../network.h"
#include "../util.h"
#include "../protocol.h"
#include "../network.h"

static int dummy_send(void *nothing,
                                struct evbuffer *source, struct evbuffer *dest);
static enum recv_ret dummy_recv(void *nothing, struct evbuffer *source,
                                struct evbuffer *dest);
static void usage(void);
static int parse_and_set_options(int n_options, char **options, 
                                 struct protocol_params_t *params);

static protocol_vtable *vtable=NULL;

/**
   This function populates 'params' according to 'options' and sets up
   the protocol vtable.

   'options' is an array like this:
   {"dummy","socks","127.0.0.1:6666"}
*/   
int
dummy_init(int n_options, char **options, 
           struct protocol_params_t *params)
{
  if (parse_and_set_options(n_options,options,params) < 0) {
    usage();
    return -1;
  }

  /* XXX memleak. */
  vtable = calloc(1, sizeof(protocol_vtable));
  if (!vtable)
    return -1;

  vtable->destroy = NULL;
  vtable->create = dummy_new;
  vtable->handshake = NULL;
  vtable->send = dummy_send;
  vtable->recv = dummy_recv;

  return 0;
}

/**
   Helper: Parses 'options' and fills 'params'.
*/ 
static int
parse_and_set_options(int n_options, char **options, 
                      struct protocol_params_t *params)
{
  struct sockaddr_storage ss_listen;
  int sl_listen;
  const char* defport;
  
  if (n_options != 3)
    return -1;

  assert(!strcmp(options[0],"dummy"));
  params->proto = DUMMY_PROTOCOL;

  if (!strcmp(options[1], "client")) {
    defport = "48988"; /* bf5c */
    params->mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[1], "socks")) {
    defport = "23548"; /* 5bf5 */
    params->mode = LSN_SOCKS_CLIENT;
  } else if (!strcmp(options[1], "server")) {
    defport = "11253"; /* 2bf5 */
    params->mode = LSN_SIMPLE_SERVER;
  } else
    return -1;

  if (resolve_address_port(options[2], 1, 1, 
                           &ss_listen, &sl_listen, defport) < 0) {
    log_warn("addr");
    return -1;
  }
  assert(sl_listen <= sizeof(struct sockaddr_storage));
  struct sockaddr *sa_listen=NULL;
  sa_listen = (struct sockaddr *)&ss_listen;
  memcpy(&params->on_address, sa_listen, sl_listen);
  params->on_address_len = sl_listen;
  
  return 0;
}

/**
   Prints dummy protocol usage information.
*/
static void
usage(void)
{
  printf("Great... You can't even form a dummy protocol line:\n"
         "dummy syntax:\n"
         "\tdummy dummy_opts\n"
         "\t'dummy_opts':\n"
         "\t\tmode ~ server|client|socks\n"
         "\t\tlisten address ~ host:port\n"
         "Example:\n"
         "\tobfsproxy dummy socks 127.0.0.1:5000\n");
}
    
/*
  This is called everytime we get a connection for the dummy
  protocol.
  
  It sets up the protocol vtable in 'proto_struct'.
*/
void *
dummy_new(struct protocol_t *proto_struct,
          struct protocol_params_t *params)
{
  proto_struct->vtable = vtable;

  /* Dodging state check. 
     This is terrible I know.*/
  return (void *)666U;
}

/**
   Responsible for sending data according to the dummy protocol.

   The dummy protocol just puts the data of 'source' in 'dest'.
*/
static int
dummy_send(void *nothing,
           struct evbuffer *source, struct evbuffer *dest) {
  (void)nothing;

  return evbuffer_add_buffer(dest,source);
}

/*
  Responsible for receiving data according to the dummy protocol.

  The dummy protocol just puts the data of 'source' into 'dest'.
*/
static enum recv_ret
dummy_recv(void *nothing,
           struct evbuffer *source, struct evbuffer *dest) {
  (void)nothing;
  
  if (evbuffer_add_buffer(dest,source)<0)
    return RECV_BAD;
  else
    return RECV_GOOD;
}
