/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"

#include "protocols/dummy.h"
#include "protocols/x_dsteg.h"
/*#include "protocols/obfs2.h"*/

/**
    All supported protocols should be put in this array.
    It's used by main.c.
*/
const proto_vtable *const supported_protocols[] =
{
  &p_dummy_vtable,
  &p_x_dsteg_vtable,
  /*&obfs2_vtable,*/
};
const size_t n_supported_protocols =
  sizeof(supported_protocols)/sizeof(supported_protocols[0]);

/**
   This function dispatches (by name) creation of a |config_t|
   to the appropriate protocol-specific initalization function.
 */
config_t *
config_create(int n_options, const char *const *options)
{
  size_t i;
  for (i = 0; i < n_supported_protocols; i++)
    if (!strcmp(*options, supported_protocols[i]->name))
      /* Remove the first element of 'options' (which is always the
         protocol name) from the list passed to the init method. */
      return supported_protocols[i]->config_create(n_options - 1, options + 1);

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
