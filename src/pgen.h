/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef PGEN_H
#define PGEN_H

// NOTE: this must be kept in sync with steg/payloads.h

#define TYPE_SERVICE_DATA 0x1
#define TYPE_HTTP_REQUEST 0x2
#define TYPE_HTTP_RESPONSE 0x4

/* struct for reading in the payload_gen dump file */
struct pentry_header {
  uint16_t ptype;
  uint32_t length;
  uint16_t port; /* network format */
};

#endif
