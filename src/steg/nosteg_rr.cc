/*  Copyright (c) 2011, SRI International

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

    * Neither the names of the copyright owners nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Contributors: Zack Weinberg, Vinod Yegneswaran
    See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include <event2/buffer.h>

namespace {
struct nosteg_rr : steg_t
{
  bool can_transmit : 1;
  STEG_DECLARE_METHODS(nosteg_rr);
};
}

STEG_DEFINE_MODULE(nosteg_rr);

nosteg_rr::nosteg_rr(bool is_clientside)
  : steg_t(is_clientside),
    can_transmit(is_clientside)
{
}

nosteg_rr::~nosteg_rr()
{
}

size_t
nosteg_rr::transmit_room(conn_t *)
{
  return can_transmit ? SIZE_MAX : 0;
}

int
nosteg_rr::transmit(struct evbuffer *source, conn_t *conn)
{
  log_assert(can_transmit);

  struct evbuffer *dest = conn->outbound();

  log_debug(conn, "transmitting %lu bytes",
            (unsigned long)evbuffer_get_length(source));

  if (evbuffer_add_buffer(dest, source)) {
    log_warn(conn, "failed to transfer buffer");
    return -1;
  }

  can_transmit = false;
  if (is_clientside) {
    conn_cease_transmission(conn);
  } else {
    conn_close_after_transmit(conn);
  }

  return 0;
}

int
nosteg_rr::receive(conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();

  log_debug(conn, "%s-side receiving %lu bytes",
            is_clientside ? "client" : "server",
            (unsigned long)evbuffer_get_length(source));

  if (evbuffer_add_buffer(dest, source)) {
    log_warn(conn, "failed to transfer buffer");
    return -1;
  }

  if (is_clientside) {
    conn_expect_close(conn);
  } else {
    can_transmit = true;
    conn_transmit_soon(conn, 100);
  }

  return 0;
}
