#ifndef CHOP_CIRCUIT_H
#define CHOP_CIRCUIT_H

#include <unordered_set>

#include "chop_blk.h"
//#include "chop_conn.h"
using std::unordered_set;
using std::vector;

using namespace chop_blk;



namespace chop_protocol {

struct chop_config_t;
struct chop_conn_t;
 
struct chop_circuit_t : circuit_t
{
  transmit_queue tx_queue;
  reassembly_queue recv_queue;
  unordered_set<chop_conn_t *> downstreams;
  gcm_encryptor *send_crypt;
  ecb_encryptor *send_hdr_crypt;
  gcm_decryptor *recv_crypt;
  ecb_decryptor *recv_hdr_crypt;
  chop_config_t *config;

  uint32_t circuit_id;
  uint32_t last_acked;
  uint32_t dead_cycles;
  bool received_fin : 1;
  bool sent_fin : 1;
  bool upstream_eof : 1;

  //For debug and tracking performance we keep track of average room
  //desirable and offered size
  double avg_desirable_size;
  double avg_available_size;
  unsigned long number_of_room_requests;
  CIRCUIT_DECLARE_METHODS(chop);

  //override the constructor so we can initialize the transmit queue
  chop_circuit_t(bool retransmit);
  // Shortcut some unnecessary conversions for callers within this file.
  void add_downstream(chop_conn_t *conn);
  void drop_downstream(chop_conn_t *conn);

  int send_special(opcode_t f, struct evbuffer *payload);
  int send_targeted(chop_conn_t *conn);
  int send_targeted(chop_conn_t *conn, size_t blocksize);
  int send_targeted(chop_conn_t *conn, size_t d, size_t p, opcode_t f,
                    struct evbuffer *payload);
  int maybe_send_ack();
  int retransmit();

  /** 
      check all conn for steg protocol data and send them
      if there's any
  */
  int send_all_steg_data();
  /** the same as send targeted but it reads the data from
      conn->steg->cfg()->protocol_data and set opcode = op_STEG0
  */
  int send_targeted_steg_data(chop_conn_t *conn, size_t blocksize);

  /**
     checks the steg module of all connections to see if they have
     protocol data to send
     
     @return the first connection whose steg has data to send
  */
  chop_conn_t* check_for_steg_protocol_data();
  chop_conn_t* pick_connection(size_t desired, size_t minimum,
                               size_t *blocksize);

  int recv_block(uint32_t seqno, opcode_t op, evbuffer *payload, steg_config_t *steg_cfg);
  int process_queue();
  int check_for_eof();

  uint32_t axe_interval();
  uint32_t flush_interval();
};
}

#endif
