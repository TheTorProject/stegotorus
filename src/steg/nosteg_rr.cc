/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include <event2/buffer.h>

namespace {
  struct nosteg_rr_steg_config_t : steg_config_t
  {
    STEG_CONFIG_DECLARE_METHODS(nosteg_rr);
  };

  struct nosteg_rr_steg_t : steg_t
  {
    nosteg_rr_steg_config_t *config;
    conn_t *conn;

    bool can_transmit : 1;
    bool did_transmit : 1;

    nosteg_rr_steg_t(nosteg_rr_steg_config_t *cf, conn_t *cn);
    STEG_DECLARE_METHODS(nosteg_rr);
  };
}

STEG_DEFINE_MODULE(nosteg_rr);

nosteg_rr_steg_config_t::nosteg_rr_steg_config_t(config_t *cfg)
  : steg_config_t(cfg)
{
}

nosteg_rr_steg_config_t::~nosteg_rr_steg_config_t()
{
}

steg_t *
nosteg_rr_steg_config_t::steg_create(conn_t *conn)
{
  return new nosteg_rr_steg_t(this, conn);
}

nosteg_rr_steg_t::nosteg_rr_steg_t(nosteg_rr_steg_config_t *cf,
                                   conn_t *cn)
  : config(cf), conn(cn),
    can_transmit(cf->cfg->mode != LSN_SIMPLE_SERVER),
    did_transmit(false)
{
}

nosteg_rr_steg_t::~nosteg_rr_steg_t()
{
}

steg_config_t *
nosteg_rr_steg_t::cfg()
{
  return config;
}

size_t
nosteg_rr_steg_t::transmit_room(size_t pref, size_t, size_t)
{
  return can_transmit ? pref : 0;
}

int
nosteg_rr_steg_t::transmit(struct evbuffer *source)
{
  log_assert(can_transmit);

  struct evbuffer *dest = conn->outbound();

  log_debug(conn, "transmitting %lu bytes",
            (unsigned long)evbuffer_get_length(source));

  if (evbuffer_add_buffer(dest, source)) {
    log_warn(conn, "failed to transfer buffer");
    return -1;
  }

  did_transmit = true;
  can_transmit = false;
  conn->cease_transmission();

  return 0;
}

int
nosteg_rr_steg_t::receive(struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();

  log_debug(conn, "%s-side receiving %lu bytes",
            config->cfg->mode == LSN_SIMPLE_SERVER ? "server" : "client",
            (unsigned long)evbuffer_get_length(source));

  if (evbuffer_add_buffer(dest, source)) {
    log_warn(conn, "failed to transfer buffer");
    return -1;
  }

  if (config->cfg->mode != LSN_SIMPLE_SERVER) {
    conn->expect_close();
  } else if (!did_transmit) {
    can_transmit = true;
    conn->transmit_soon(100);
  }

  return 0;
}
