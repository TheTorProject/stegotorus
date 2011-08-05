/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "steg.h"

/**
   All supported steganography modules go in this array.
*/
const steg_vtable *const supported_steg[] =
{
};
const size_t n_supported_steg =
  sizeof(supported_steg)/sizeof(supported_steg[0]);

/* Instantiate a steg module by name. */
steg_t *
steg_new(const char *name)
{
  size_t i;
  for (i = 0; i < n_supported_steg; i++)
    if (!strcmp(name, supported_steg[i]->name))
      return supported_steg[i]->state_new(NULL, /*is_clientside=*/1);
  return NULL;
}

/* Instantiate a steg module by detection. */
steg_t *
steg_detect(conn_t *conn)
{
  size_t i;
  for (i = 0; i < n_supported_steg; i++)
    if (supported_steg[i]->detect(conn))
      return supported_steg[i]->state_new(NULL, /*is_clientside=*/0);
  return NULL;
}

/* Vtable shims. */

void
steg_del(steg_t *state)
{
  if (!state) return;
  state->vtable->state_del(state);
}

size_t
steg_transmit_room(steg_t *state, conn_t *conn)
{
  return state->vtable->transmit_room(state, conn);
}

int
steg_transmit(steg_t *state, struct evbuffer *source, conn_t *conn)
{
  return state->vtable->transmit(state, source, conn);
}

enum recv_ret
steg_receive(steg_t *state, conn_t *conn, struct evbuffer *dest)
{
  return state->vtable->receive(state, conn, dest);
}
