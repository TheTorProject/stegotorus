/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "steg.h"

/* Report whether a named steg-module is supported. */

int
steg_is_supported(const char *name)
{
  const steg_module *const *s;
  for (s = supported_stegs; *s; s++)
    if (!strcmp(name, (**s).name))
      return 1;
  return 0;
}

/* Instantiate a steg module by name. */
steg_t *
steg_new(const char *name, bool is_clientside)
{
  const steg_module *const *s;
  for (s = supported_stegs; *s; s++)
    if (!strcmp(name, (**s).name))
      return (**s).new_(is_clientside);
  return NULL;
}

/* Define this here rather than in the class definition so that the
   vtable will be emitted in only one place. */
steg_t::~steg_t() {}
