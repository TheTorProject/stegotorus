#ifndef CHOP_CONN_H
#define CHOP_CONN_H

#include <yaml-cpp/yaml.h>

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
//#include "crypt.h"
//#include "modus_operandi.h"
//#include "chop_blk.h"
//#include "chop_handshaker.h"
//#include "connections.h"
//#include "rng.h"

//#include "steg.h"

namespace chop_protocol  {

struct chop_circuit_t;
struct chop_config_t;

struct chop_conn_t : conn_t
{
  chop_config_t *config;
  chop_circuit_t *upstream;
  steg_t *steg;
  struct evbuffer *recv_pending;
  uint8_t *originally_received; //Keep a copy of pending in case we need 
  size_t received_length;
  //to become a transparent proxy
  struct event *must_send_timer;
  bool sent_handshake : 1;
  bool no_more_transmissions : 1;

  CONN_DECLARE_METHODS(chop);

  int recv_handshake();
  int send(struct evbuffer *block);

  void send();
  bool must_send_p() const;
  static void must_send_timeout(evutil_socket_t, short, void *arg);

  /**
   In case the connection is transparentized or needed to be closed
   then chop circuit/protocol should no longer influence the
   status of the connection
 */
  void emancipate_from_upstream();

};
}

#endif
