/* Copyright 2013, Tor Project Inc.
 * See LICENSE for other credits and copying information
 *
 * AUTHOR:
 *    Vmon (vmon@riseup.net): August 2013: initial version
 *  
 * I have not used it yet. Transparent proxy seems to be an 
 * easier approach.
 */

#ifndef TRANSPARENT_CIRCUIT_H
#define TRANSPARENT_CIRCUIT_H

/**
 If active probing is detected or the user has no intention
 to use stegotorus, the connection will be added to a 
 transparent circuit so data just get copied between
 inbound and outbound
*/
struct transparent_circuit_t : circuit_t
{
  chop_conn_t * downstream;

  uint32_t circuit_id;
  bool received_fin : 1;
  bool sent_fin : 1;
  bool upstream_eof : 1;

  //For debug and tracking performance we keep track of average room
  //desirable and offered size
  CIRCUIT_DECLARE_METHODS(transparent);

  // Shortcut some unnecessary conversions for callers within this file.
  void add_downstream(chop_conn_t *conn);
  void drop_downstream(chop_conn_t *conn);

  int send_special(opcode_t f, struct evbuffer *payload);
  int send_targeted(chop_conn_t *conn);
  int send_targeted(chop_conn_t *conn, size_t blocksize);
  int send_targeted(chop_conn_t *conn, size_t d, size_t p, opcode_t f,
                    struct evbuffer *payload);
  int recv_block(uint32_t seqno, opcode_t op, evbuffer *payload, conn_t *conn);
  int process_queue();
  int check_for_eof();

  uint32_t axe_interval() {
    // This function must always return a number which is larger than
    // the maximum possible number that *our peer's* flush_interval()
    // could have returned; otherwise, we might axe the connection when
    // it was just that there was nothing to say for a while.
    // For simplicity's sake, right now we hardwire this to be 30 minutes.
    return 30 * 60 * 1000;
  }
  uint32_t flush_interval() {
    // 10*60*1000 lies between 2^19 and 2^20.
    uint32_t shift = std::max(1u, std::min(19u, dead_cycles));
    uint32_t xv = std::max(1u, std::min(10u * 60 * 1000, 1u << shift));
    //TODO: this needs to be formalised
    if (dead_cycles == 0)
      return 100;

    return rng_range_geom(20 * 60 * 1000, xv) + 100;
  }
};

#endif /* transparent_circuit.h */
