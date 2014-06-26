/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "protocol.h"

/**
   Return 1 if 'name' is the name of a supported protocol, otherwise 0.
*/
int
config_is_supported(const char *name)
{
  const proto_module *const *p;
  for (p = supported_protos; *p; p++)
    if (!strcmp(name, (*p)->name))
      return 1;

  return 0;
}

/**
   This function dispatches (by name) creation of a |config_t|
   to the appropriate protocol-specific initalization function.
 */
config_t *
config_create(int n_options, const char *const *options, modus_operandi_t& mo)
{
  const proto_module *const *p;
  for (p = supported_protos; *p; p++)
    if (!strcmp(options[0], (*p)->name))
      /* Remove the first element of 'options' (which is always the
         protocol name) from the list passed to the init method. */
      return (*p)->config_create(n_options - 1, options + 1, mo);

  return NULL;
}

/* Define this here rather than in the class definition so that the
   vtable will be emitted in only one place. */
config_t::~config_t() {}
