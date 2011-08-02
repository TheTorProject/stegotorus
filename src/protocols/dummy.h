/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/
#ifndef PROTOCOL_DUMMY_H
#define PROTOCOL_DUMMY_H

extern const protocol_vtable dummy_vtable;

#ifdef PROTOCOL_DUMMY_PRIVATE

/* ==========
   These definitions are not part of the dummy protocol interface.
   They're exposed here so that the unit tests can use them.
   ==========
*/

#include "../network.h"
#include "../protocol.h"

/* Dummy presently needs only the obligatory extensions to the generic
   protocol structures, but we have shims for future expansion, and
   also because, if you're using dummy as a template, you probably
   will want to extend the generic structures. */

typedef struct dummy_config_t {
  config_t super;
  struct evutil_addrinfo *listen_addr;
  struct evutil_addrinfo *target_addr;
  enum listen_mode mode;
} dummy_config_t;

typedef struct dummy_conn_t {
  conn_t super;
} dummy_conn_t;

#endif

#endif
