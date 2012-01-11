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
#include <stdio.h>

#define DUMMY_PORT 3333

namespace {
struct dummy : steg_t
{
  bool have_transmitted : 1;
  bool have_received : 1;
  STEG_DECLARE_METHODS(dummy);
};
}

STEG_DEFINE_MODULE(dummy,
                   1024,  /* client-server max data rate - made up */
                   10240, /* server-client max data rate - ditto */
                   1,     /* max concurrent connections per IP */
                   1);     /* max concurrent IPs */


dummy::dummy(bool is_clientside)
  : have_transmitted(false), have_received(false)
{
  this->is_clientside = is_clientside;
}

dummy::~dummy()
{
}

/** Determine whether a connection should be processed by this
    steganographer. */
bool
dummy::detect(conn_t *conn)
{
  struct evutil_addrinfo *addrs = conn->cfg->get_listen_addrs(0);
  if (!addrs) {
    log_debug("no listen addrs\n");
    return 0;
  }

  struct sockaddr_in* sin = (struct sockaddr_in*) addrs->ai_addr;

  if (sin->sin_port == htons(DUMMY_PORT))
    return 1;

  return 0;

}

size_t
dummy::transmit_room(conn_t *)
{

  if (have_transmitted)
    return 0;

  if (is_clientside)
    return SIZE_MAX;

  if (!have_received)
    return 0;

  return SIZE_MAX;
}







int
dummy::transmit(struct evbuffer *source, conn_t *conn)
{
  struct evbuffer *dest = conn_get_outbound(conn);

  fprintf(stderr, "transmitting %d\n", (int) evbuffer_get_length(source));;


  if (evbuffer_add_buffer(dest, source)) {
    fprintf(stderr, "failed to transfer buffer\n");
  }


  
  conn_cease_transmission(conn);
  this->have_transmitted = 1;
  return 0;

}






int
dummy::receive(conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn_get_inbound(conn);


  fprintf(stderr, "receiving %d\n", (int) evbuffer_get_length(source));

  if (evbuffer_add_buffer(dest, source)) {
    fprintf(stderr, "failed to transfer buffer\n");
  }

 



  this->have_received = 1;
  conn_transmit_soon(conn, 100);
  return 0;
}
