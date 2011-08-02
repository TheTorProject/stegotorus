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

/* Dummy presently needs no extensions to the generic protocol
   structures, but we have shims for future expansion, and also
   because, if you're using dummy as a template, you probably will
   want to extend the generic structures. */

typedef struct dummy_listener_t {
  listener_t super;
} dummy_listener_t;

typedef struct dummy_protocol_t {
  protocol_t super;
} dummy_protocol_t;

#endif

#endif
