/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/
#ifndef PROTOCOL_X_DSTEG_H
#define PROTOCOL_X_DSTEG_H

extern const proto_vtable p_x_dsteg_vtable;

#ifdef PROTOCOL_X_DSTEG_PRIVATE

/* ==========
   These definitions are not part of the x_dsteg protocol interface.
   They're exposed here so that the unit tests can use them.
   ==========
*/

#include "connections.h"
#include "protocol.h"
#include "steg.h"

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

#endif

#endif
