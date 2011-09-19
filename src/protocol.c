/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "protocol.h"

/**
   Return 1 if 'name' is the name of a supported protocol, otherwise 0.
*/
int
config_is_supported(const char *name)
{
  const proto_vtable *const *p;
  for (p = supported_protocols; *p; p++)
    if (!strcmp(name, (*p)->name))
      return 1;

  return 0;
}

/**
   This function dispatches (by name) creation of a |config_t|
   to the appropriate protocol-specific initalization function.
 */
config_t *
config_create(int n_options, const char *const *options)
{
  const proto_vtable *const *p;
  for (p = supported_protocols; *p; p++)
    if (!strcmp(options[0], (*p)->name))
      /* Remove the first element of 'options' (which is always the
         protocol name) from the list passed to the init method. */
      return (*p)->config_create(n_options - 1, options + 1);

  return NULL;
}

/**
   This function destroys the protocol-specific part of a listener object.
*/
void
config_free(config_t *cfg)
{
  cfg->vtable->config_free(cfg);
}

struct evutil_addrinfo *
config_get_listen_addrs(config_t *cfg, size_t n)
{
  return cfg->vtable->config_get_listen_addrs(cfg, n);
}

struct evutil_addrinfo *
config_get_target_addr(config_t *cfg)
{
  return cfg->vtable->config_get_target_addr(cfg);
}
