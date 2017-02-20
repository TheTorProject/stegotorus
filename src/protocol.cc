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
   this variant configure the protocol using user specified
   commandline options
 */
config_t *
config_create(int n_options, const char *const *options)
{
  const proto_module *const *p;
  for (p = supported_protos; *p; p++)
    if (!strcmp(options[0], (*p)->name))
      /* Remove the first element of 'options' (which is always the
         protocol name) from the list passed to the init method. */
      return (*p)->config_create(n_options - 1, options + 1);

  return NULL;
}

/**
   overload of config_create but using the YAML Node
   in the config file

   @param protocol_node reference to the node defining the prtocol spec in the
          config file
 */
config_t *
config_create(const YAML::Node& protocol_node)
{
  const proto_module *const *p;
  try {
    if (protocol_node["name"]) {
      for (p = supported_protos; *p; p++) {
        log_debug("searching for protocol class %s", (protocol_node["name"].as<std::string>().c_str()));
        if ((protocol_node["name"].as<std::string>() == (*p)->name))
          /* Remove the first element of 'options' (which is always the
             protocol name) from the list passed to the init method. */
          return (*p)->config_create_from_yaml(protocol_node);
        
      }
    } else {
      log_abort("bad protocol config format, protocol name is not specified");
    }
  } catch( YAML::RepresentationException &e ) {
      log_abort("bad protocol config format %s", e.what());
    }

  return NULL;
}

/* Define this here rather than in the class definition so that the
   vtable will be emitted in only one place. */
config_t::~config_t() {}
