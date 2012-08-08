/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include <event2/buffer.h>
#include <curl/curl.h>
#include <vector>

using namespace std;

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include "rng.h"

/** here we initiate our payload strategy (it should be)based on the config 
    file so I include all available payload servers. The global object is of
    PayloadServer type though
*/
#include "payload_server.h"
#include "trace_payload_server.h"
#include "apache_payload_server.h"

#include "cookies.h"
#include "swfSteg.h"
#include "pdfSteg.h"
#include "jsSteg.h"
#include "base64.h"
#include "b64cookies.h"

#include "http.h"

namespace {

  struct http_trace_steg_config_t : http_steg_config_t
  {
    STEG_CONFIG_DECLARE_METHODS(http_trace);
  };


  struct http_trace_steg_t : http_steg_t
  {
    http_trace_steg_t(http_trace_steg_config_t *cf, conn_t *cn);
    STEG_DECLARE_METHODS(http_trace);

  };

}

STEG_DEFINE_MODULE(http_trace);

http_trace_steg_config_t::http_trace_steg_config_t(config_t *cfg)
  : http_steg_config_t(cfg)
{
}

http_trace_steg_config_t::~http_trace_steg_config_t()
{
  //delete payload_server; maybe we don't need it

}

steg_t *
http_trace_steg_config_t::steg_create(conn_t *conn)
{
  return new http_trace_steg_t(this, conn);
}

http_trace_steg_t::http_trace_steg_t(http_trace_steg_config_t *cf, conn_t *cn): http_steg_t((http_steg_config_t*)cf, cn)
{
}

http_trace_steg_t::~http_trace_steg_t()
{
}

steg_config_t *
http_trace_steg_t::cfg()
{
  return config;
}

size_t
http_trace_steg_t::transmit_room(size_t pref, size_t lo, size_t hi)
{
  return http_steg_t::transmit_room(pref,  lo, hi);
}

int
http_trace_steg_t::transmit(struct evbuffer *source)
{
  return http_steg_t::transmit(source);
}

int
http_trace_steg_t::receive(struct evbuffer *dest)
{
  return http_steg_t::receive(dest);
}
 
