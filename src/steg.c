/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "steg.h"

/* Report whether a named steg-module is supported. */

int
steg_is_supported(const char *name)
{
  const steg_vtable *const *s;
  for (s = supported_stegs; *s; s++)
    if (!strcmp(name, (*s)->name))
      return 1;
  return 0;
}

/* Instantiate a steg module by name. */
steg_t *
steg_new(const char *name)
{
  const steg_vtable *const *s;
  for (s = supported_stegs; *s; s++)
    if (!strcmp(name, (*s)->name))
      return (*s)->new(NULL, /*is_clientside=*/1);
  return NULL;
}

/* Instantiate a steg module by detection. */
steg_t *
steg_detect(conn_t *conn)
{
  const steg_vtable *const *s;
  for (s = supported_stegs; *s; s++)
    if ((*s)->detect(conn))
      return (*s)->new(NULL, /*is_clientside=*/0);
  return NULL;
}

/* Vtable shims. */

void
steg_del(steg_t *state)
{
  if (!state) return;
  state->vtable->del(state);
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
