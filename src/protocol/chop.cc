/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "chop_blk.h"
#include "connections.h"
#include "protocol.h"
#include "rng.h"
#include "steg.h"

#include <tr1/unordered_map>
#include <tr1/unordered_set>
#include <vector>
#include <algorithm>

#include <event2/event.h>

/* The chopper is the core StegoTorus protocol implementation.
   For its design, see doc/chopper.txt.  Note that it is still
   being implemented, and may change incompatibly.  */

using std::tr1::unordered_map;
using std::tr1::unordered_set;
using std::vector;
using std::make_pair;
using std::min;

using namespace chop_blk;

struct chop_config_t;
struct chop_circuit_t;

typedef unordered_map<uint32_t, chop_circuit_t *> chop_circuit_table;

struct chop_conn_t : conn_t
{
  chop_config_t *config;
  chop_circuit_t *upstream;
  steg_t *steg;
  struct evbuffer *recv_pending;
  struct event *must_send_timer;
  bool sent_handshake : 1;
  bool no_more_transmissions : 1;

  CONN_DECLARE_METHODS(chop);

  int recv_handshake();
  int send(struct evbuffer *block);

  void send();
  bool must_send_p() const;
  static void must_send_timeout(evutil_socket_t, short, void *arg);
};

struct chop_circuit_t : circuit_t
{
  reassembly_queue recv_queue;
  unordered_set<chop_conn_t *> downstreams;
  gcm_encryptor *send_crypt;
  ecb_encryptor *send_hdr_crypt;
  gcm_decryptor *recv_crypt;
  ecb_decryptor *recv_hdr_crypt;
  chop_config_t *config;

  uint32_t circuit_id;
  uint32_t send_seq;
  uint32_t dead_cycles;
  bool received_fin : 1;
  bool sent_fin : 1;
  bool upstream_eof : 1;

  CIRCUIT_DECLARE_METHODS(chop);

  // Shortcut some unnecessary conversions for callers within this file.
  void add_downstream(chop_conn_t *conn);
  void drop_downstream(chop_conn_t *conn);

  int send_special(opcode_t f, struct evbuffer *payload);
  int send_targeted(chop_conn_t *conn);
  int send_targeted(chop_conn_t *conn, size_t blocksize);
  int send_targeted(chop_conn_t *conn, size_t d, size_t p, opcode_t f,
                    struct evbuffer *payload);

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
     check the steg module of all connection to see if they have
     protocol data to send
     
     @return the first connection whose steg has data to send
  */
  chop_conn_t* check_for_steg_protocol_data();
  chop_conn_t *pick_connection(size_t desired, size_t *blocksize);

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
    return rng_range_geom(20 * 60 * 1000, xv) + 100;
  }
};

struct chop_config_t : config_t
{
  struct evutil_addrinfo *up_address;
  vector<struct evutil_addrinfo *> down_addresses;
  vector<steg_config_t *> steg_targets;
  chop_circuit_table circuits;
  bool trace_packets;
  bool encryption;

  CONFIG_DECLARE_METHODS(chop);
};

// Configuration methods

chop_config_t::chop_config_t()
{
  ignore_socks_destination = true;
  trace_packets = false;
  encryption = true;
}

chop_config_t::~chop_config_t()
{
  if (up_address)
    evutil_freeaddrinfo(up_address);
  for (vector<struct evutil_addrinfo *>::iterator i = down_addresses.begin();
       i != down_addresses.end(); i++)
    evutil_freeaddrinfo(*i);

  for (vector<steg_config_t *>::iterator i = steg_targets.begin();
       i != steg_targets.end(); i++)
    delete *i;

  for (chop_circuit_table::iterator i = circuits.begin();
       i != circuits.end(); i++)
    if (i->second)
      delete i->second;
}

bool
chop_config_t::init(int n_options, const char *const *options)
{
  const char* defport;
  int listen_up;
  int i;

  if (n_options < 3) {
    log_warn("chop: not enough parameters");
    goto usage;
  }

  if (!strcmp(options[0], "client")) {
    defport = "48988"; // bf5c
    mode = LSN_SIMPLE_CLIENT;
    listen_up = 1;
  } else if (!strcmp(options[0], "socks")) {
    defport = "23548"; // 5bf5
    mode = LSN_SOCKS_CLIENT;
    listen_up = 1;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; // 2bf5
    mode = LSN_SIMPLE_SERVER;
    listen_up = 0;
  } else
    goto usage;

  while (options[1][0] == '-') {
    if (!strncmp(options[1], "--server-key=", 13)) {
      // accept and ignore (for now) client only
      if (mode == LSN_SIMPLE_SERVER) {
        log_warn("chop: --server-key option is not valid in server mode");
        goto usage;
      }
    } else if (!strcmp(options[1], "--trace-packets")) {
      trace_packets = true;
      log_enable_timestamps();
    } else if (!strcmp(options[1], "--disable-encryption")) {
      encryption = false;
    } else {
      log_warn("chop: unrecognized option '%s'", options[1]);
      goto usage;
    }
    options++;
    n_options--;
  }

  up_address = resolve_address_port(options[1], 1, listen_up, defport);
  if (!up_address) {
    log_warn("chop: invalid up address: %s", options[1]);
    goto usage;
  }

  // From here on out, arguments alternate between downstream
  // addresses and steg targets.
  for (i = 2; i < n_options; i++) {
    struct evutil_addrinfo *addr =
      resolve_address_port(options[i], 1, !listen_up, NULL);
    if (!addr) {
      log_warn("chop: invalid down address: %s", options[i]);
      goto usage;
    }
    down_addresses.push_back(addr);

    i++;
    if (i == n_options) {
      log_warn("chop: missing steganographer for %s", options[i-1]);
      goto usage;
    }

    if (!steg_is_supported(options[i])) {
      log_warn("chop: steganographer '%s' not supported", options[i]);
      goto usage;
    }
    steg_targets.push_back(steg_new(options[i], this));
  }
  return true;

 usage:
  log_warn("chop syntax:\n"
           "\tchop <mode> <up_address> (<down_address> [<steg>])...\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tup_address, down_address ~ host:port\n"
           "\t\tA steganographer is required for each down_address.\n"
           "\t\tThe down_address list is still required in socks mode.\n"
           "Examples:\n"
           "\tstegotorus chop client 127.0.0.1:5000 "
           "192.168.1.99:11253 http 192.168.1.99:11254 skype\n"
           "\tstegotorus chop server 127.0.0.1:9005 "
           "192.168.1.99:11253 http 192.168.1.99:11254 skype");
  return false;
}

struct evutil_addrinfo *
chop_config_t::get_listen_addrs(size_t n) const 
{
  if (mode == LSN_SIMPLE_SERVER) {
    if (n < down_addresses.size())
      return down_addresses[n];
  } else {
    if (n == 0)
      return up_address;
  }
  return 0;
}

struct evutil_addrinfo *
chop_config_t::get_target_addrs(size_t n) const
{
  if (mode == LSN_SIMPLE_SERVER) {
    if (n == 0)
      return up_address;
  } else {
    if (n < down_addresses.size())
      return down_addresses[n];
  }
  return NULL;
}

const steg_config_t *
chop_config_t::get_steg(size_t n) const
{
  if (n < steg_targets.size())
    return steg_targets[n];
  return NULL;
}

// Circuit methods

const char passphrase[] =
  "did you buy one of therapist reawaken chemists continually gamma pacifies?";

circuit_t *
chop_config_t::circuit_create(size_t)
{
  chop_circuit_t *ckt = new chop_circuit_t;
  ckt->config = this;

  key_generator *kgen = 0;

  if (encryption)
    kgen = key_generator::from_passphrase((const uint8_t *)passphrase,
                                          sizeof(passphrase) - 1,
                                          0, 0, 0, 0);

  if (mode == LSN_SIMPLE_SERVER) {
    if (encryption) {
      ckt->send_crypt     = gcm_encryptor::create(kgen, 16);
      ckt->send_hdr_crypt = ecb_encryptor::create(kgen, 16);
      ckt->recv_crypt     = gcm_decryptor::create(kgen, 16);
      ckt->recv_hdr_crypt = ecb_decryptor::create(kgen, 16);
    } else {
      ckt->send_crypt     = gcm_encryptor::create_noop();
      ckt->send_hdr_crypt = ecb_encryptor::create_noop();
      ckt->recv_crypt     = gcm_decryptor::create_noop();
      ckt->recv_hdr_crypt = ecb_decryptor::create_noop();
    }
  } else {
    if (encryption) {
      ckt->recv_crypt     = gcm_decryptor::create(kgen, 16);
      ckt->recv_hdr_crypt = ecb_decryptor::create(kgen, 16);
      ckt->send_crypt     = gcm_encryptor::create(kgen, 16);
      ckt->send_hdr_crypt = ecb_encryptor::create(kgen, 16);
    } else {
      ckt->recv_crypt     = gcm_decryptor::create_noop();
      ckt->recv_hdr_crypt = ecb_decryptor::create_noop();
      ckt->send_crypt     = gcm_encryptor::create_noop();
      ckt->send_hdr_crypt = ecb_encryptor::create_noop();
    }

    std::pair<chop_circuit_table::iterator, bool> out;
    do {
      do {
        rng_bytes((uint8_t *)&ckt->circuit_id, sizeof(ckt->circuit_id));
      } while (!ckt->circuit_id);

      out = circuits.insert(make_pair(ckt->circuit_id, (chop_circuit_t *)0));
    } while (!out.second);

    out.first->second = ckt;
  }

  delete kgen;
  return ckt;
}

chop_circuit_t::chop_circuit_t()
{
}

chop_circuit_t::~chop_circuit_t()
{
  delete send_crypt;
  delete send_hdr_crypt;
  delete recv_crypt;
  delete recv_hdr_crypt;
}

void
chop_circuit_t::close()
{
  if (!sent_fin || !received_fin || !upstream_eof) {
    log_warn(this, "destroying active circuit: fin%c%c eof%c ds=%lu",
             sent_fin ? '+' : '-', received_fin ? '+' : '-',
             upstream_eof ? '+' : '-',
             (unsigned long)downstreams.size());
  }

  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;
    conn->upstream = NULL;
    conn_do_flush(conn);
  }
  downstreams.clear();

  // The IDs for old circuits are preserved for a while (at present,
  // indefinitely; FIXME: purge them on a timer) against the
  // possibility that we'll get a junk connection for one of them
  // right after we close it (same deal as the TIME_WAIT state in
  // TCP).  Note that we can hit this case for the *client* if the
  // cover protocol includes a mandatory reply to every client message
  // and the hidden channel closed s->c before c->s: the circuit will
  // get destroyed on the client side after the c->s FIN, and the
  // mandatory reply will be to a stale circuit.
  chop_circuit_table::iterator out;
  out = config->circuits.find(circuit_id);
  log_assert(out != config->circuits.end());
  log_assert(out->second == this);
  out->second = NULL;

  circuit_t::close();
}

config_t *
chop_circuit_t::cfg() const
{
  return config;
}

void
chop_circuit_t::add_downstream(chop_conn_t *conn)
{
  log_assert(conn);
  log_assert(!conn->upstream);
  conn->upstream = this;
  downstreams.insert(conn);

  log_debug(this, "added connection <%d.%d> to %s, now %lu",
            serial, conn->serial, conn->peername,
            (unsigned long)downstreams.size());

  circuit_disarm_axe_timer(this);
}

void
chop_circuit_t::add_downstream(conn_t *cn)
{
  add_downstream(dynamic_cast<chop_conn_t *>(cn));
}

void
chop_circuit_t::drop_downstream(chop_conn_t *conn)
{
  log_assert(conn);
  log_assert(conn->upstream == this);

  conn->upstream = NULL;
  downstreams.erase(conn);

  log_debug(this, "dropped connection <%d.%d> to %s, now %lu",
            serial, conn->serial, conn->peername,
            (unsigned long)downstreams.size());
  // If that was the last connection on this circuit AND we've both
  // received and sent a FIN, close the circuit.  Otherwise, if we're
  // the server, arm a timer that will kill off this circuit in a
  // little while if no new connections happen (we might've lost all
  // our connections to protocol errors, or because the steg modules
  // wanted them closed); if we're the client, send chaff in a bit,
  // to enable further transmissions from the server.
  if (downstreams.empty()) {
    if (sent_fin && received_fin) {
      circuit_do_flush(this);
    } else if (config->mode == LSN_SIMPLE_SERVER) {
      circuit_arm_axe_timer(this, axe_interval());
    } else {
      circuit_arm_flush_timer(this, flush_interval());
    }
  }
}

void
chop_circuit_t::drop_downstream(conn_t *cn)
{
  drop_downstream(dynamic_cast<chop_conn_t *>(cn));
}

int
chop_circuit_t::send()
{
  circuit_disarm_flush_timer(this);

  //First we check if there's steg data that we need to send
  if (send_all_steg_data())
    {
      log_debug("Error in transmiting steg protocol data");
    }

  struct evbuffer *xmit_pending = bufferevent_get_input(up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  size_t avail0 = avail;
  bool no_target_connection = false;

  if (downstreams.empty()) {
    log_debug(this, "no downstream connections");
    no_target_connection = true;
  } else {
    // Send at least one block, even if there is no real data to send.
    do {
      log_debug(this, "%lu bytes to send", (unsigned long)avail);
      size_t blocksize;
      chop_conn_t *target = pick_connection(avail, &blocksize);
      if (!target) {
        // this is not an error; it can happen e.g. when the server has
        // something to send immediately and the client hasn't spoken yet
        log_debug(this, "no target connection available");
        no_target_connection = true;
        break;
      }

      if (send_targeted(target, blocksize))
        return -1;

      avail = evbuffer_get_length(xmit_pending);
    } while (avail > 0);
  }

  if (avail0 == avail) { // no forward progress
    dead_cycles++;
    log_debug(this, "%u dead cycles", dead_cycles);

    // If we're the client and we had no target connection, try
    // reopening new connections.  If we're the server, we have to
    // just twiddle our thumbs and hope the client does that.
    if (no_target_connection) {
      if (config->mode != LSN_SIMPLE_SERVER &&
          downstreams.size() < 64)
        circuit_reopen_downstreams(this);
      else
        circuit_arm_axe_timer(this, axe_interval());
    }
  }

  return check_for_eof();
}

int
chop_circuit_t::send_all_steg_data()
{

  if (downstreams.empty()) {
      log_debug(this, "no downstream connections");
      return 0;
  }

  bool no_target_connection = true;

  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *target = *i;

    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!target->steg) {
      log_debug(target, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!target->connected) {
      log_debug(target, "offers 0 bytes (not connected)");
      continue;
    }

    size_t avail0;

    //Now we check if the protocol_data has any data
    size_t avail = evbuffer_get_length(target->steg->cfg()->protocol_data_out);
    //we try to send all data
    while(avail > 0) {
      size_t desired;
      if (avail > SECTION_LEN)
        desired = SECTION_LEN;
      else
        desired = avail;

      desired += MIN_BLOCK_SIZE;

      size_t lo = MIN_BLOCK_SIZE + (desired == MIN_BLOCK_SIZE ? 0 : 1);

      log_debug(this, "target block size %lu bytes", (unsigned long)desired);

      log_debug(this, "%lu bytes to send", (unsigned long)avail);
      size_t shake = target->sent_handshake ? 0 : HANDSHAKE_LEN;
      size_t room = target->steg->transmit_room(desired + shake, lo + shake,
                                                  MAX_BLOCK_SIZE + shake);
      if (room != 0) {
        if (room < lo + shake || room >= MAX_BLOCK_SIZE + shake)
          log_abort(target, "steg size request (%lu) out of range [%lu, %lu]",
                    (unsigned long)room,
                    (unsigned long)(lo + shake),
                    (unsigned long)(MAX_BLOCK_SIZE + shake));

        log_debug(target, "offers %lu bytes (%s)", (unsigned long)room,
                  target->steg->cfg()->name());

        if (send_targeted_steg_data(target, room))
          return -1;
      }
      else {
        log_debug(target, "offers 0 bytes (%s)",
                  target->steg->cfg()->name());
      }

      avail0 = avail;
      avail = evbuffer_get_length(target->steg->cfg()->protocol_data_out);

      if (avail0 == avail) { // no forward progress
        dead_cycles++;
        log_debug(this, "%u dead cycles", dead_cycles);
        break;
      }
      else {
        no_target_connection = false;
      }
    } //while(avail > 0)
  } //for all targets

  // If we're the client and we had no target connection, try
  // reopening new connections.  If we're the server, we have to
  // just twiddle our thumbs and hope the client does that.
  if (no_target_connection) {
    if (config->mode != LSN_SIMPLE_SERVER &&
        downstreams.size() < 64)
      circuit_reopen_downstreams(this);
    else
      circuit_arm_axe_timer(this, axe_interval());
  }

  return 0;
}


int
chop_circuit_t::send_eof()
{
  upstream_eof = true;
  return send();
}

int
chop_circuit_t::send_special(opcode_t f, struct evbuffer *payload)
{
  size_t d = payload ? evbuffer_get_length(payload) : 0;
  size_t blocksize;
  log_assert(d <= SECTION_LEN);
  chop_conn_t *conn = pick_connection(d, &blocksize);
  size_t lo = MIN_BLOCK_SIZE + ((conn && !conn->sent_handshake)
                                ? HANDSHAKE_LEN : 0);

  if (!conn || (blocksize - lo < d)) {
    log_warn("no usable connection for special block "
             "(opcode %02x, need %lu bytes, have %lu)",
             (unsigned int)f, (unsigned long)(d + lo),
             (unsigned long)blocksize);
    return -1;
  }

  return send_targeted(conn, d, (blocksize - lo) - d, f, payload);
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn)
{
  //Priority with steg data
  bool steg_data_available = false;
  size_t avail = evbuffer_get_length(conn->steg->cfg()->protocol_data_out);
  if (avail > 0)
    steg_data_available = true;
  else
    avail = evbuffer_get_length(bufferevent_get_input(up_buffer));

  if (avail > SECTION_LEN)
    avail = SECTION_LEN;
  avail += MIN_BLOCK_SIZE;

  // If we have any data to transmit, ensure we do not send a block
  // that contains no data at all.
  size_t lo = MIN_BLOCK_SIZE + (avail == MIN_BLOCK_SIZE ? 0 : 1);

  // If this connection has not yet sent a handshake, it will need to.
  size_t hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += HANDSHAKE_LEN;
    hi += HANDSHAKE_LEN;
    avail += HANDSHAKE_LEN;
  }

  size_t room = conn->steg->transmit_room(avail, lo, hi);
  if (room == 0)
    log_abort(conn, "must send but cannot send");
  if (room < lo || room >= hi)
    log_abort(conn, "steg size request (%lu) out of range [%lu, %lu]",
              (unsigned long)room, (unsigned long)lo, (unsigned long)hi);

  log_debug(conn, "requests %lu bytes (%s)", (unsigned long)room,
            conn->steg->cfg()->name());

  return steg_data_available ? 
    send_targeted_steg_data(conn, room) :
    send_targeted(conn, room);
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn, size_t blocksize)
{
  size_t lo = MIN_BLOCK_SIZE, hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += HANDSHAKE_LEN;
    hi += HANDSHAKE_LEN;
  }
  log_assert(blocksize >= lo && blocksize <= hi);

  struct evbuffer *xmit_pending = bufferevent_get_input(up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  opcode_t op = op_DAT;
  
  //The original code 
  /*if (avail > blocksize - lo)
    avail = blocksize - lo;
    else if (avail > SECTION_LEN)
    avail = SECTION_LEN;*/

  if (avail > blocksize - lo || avail > SECTION_LEN)
    avail = min(blocksize - lo, SECTION_LEN);
  else if (upstream_eof && !sent_fin)
    // this block will carry the last byte of real data to be sent in
    // this direction; mark it as such
    op = op_FIN;

  return send_targeted(conn, avail, (blocksize - lo) - avail,
                       op, xmit_pending);
}

int
chop_circuit_t::send_targeted_steg_data(chop_conn_t *conn, size_t blocksize)
{
  size_t lo = MIN_BLOCK_SIZE, hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += HANDSHAKE_LEN;
    hi += HANDSHAKE_LEN;
  }
  log_assert(blocksize >= lo && blocksize <= hi);

  size_t avail = evbuffer_get_length(conn->steg->cfg()->protocol_data_out);
  opcode_t op = op_STEG0;

  if (avail > blocksize - lo || avail > SECTION_LEN)
    avail = min(blocksize - lo, SECTION_LEN);
  else if (upstream_eof && !sent_fin)
    // this block will carry the last byte of real data to be sent in
    // this direction; mark it as such
    op = op_STEG_FIN;

  return send_targeted(conn, avail, (blocksize - lo) - avail,
                       op, conn->steg->cfg()->protocol_data_out);
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn, size_t d, size_t p, opcode_t f,
                              struct evbuffer *payload)
{
  log_assert(payload || d == 0);
  log_assert(d <= SECTION_LEN);
  log_assert(p <= SECTION_LEN);

  struct evbuffer *block = evbuffer_new();
  if (!block) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }

  size_t blocksize = d + p + MIN_BLOCK_SIZE;
  struct evbuffer_iovec v;
  if (evbuffer_reserve_space(block, blocksize, &v, 1) != 1 ||
      v.iov_len < blocksize) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }
  v.iov_len = blocksize;

  header hdr(send_seq, d, p, f, *send_hdr_crypt);
  log_assert(hdr.valid(send_seq));
  memcpy(v.iov_base, hdr.nonce(), HEADER_LEN);

  uint8_t encodebuf[SECTION_LEN*2];
  if (payload) {
    if (evbuffer_copyout(payload, encodebuf, d) != (ssize_t)d) {
      log_warn(conn, "failed to extract payload");
      evbuffer_free(block);
      return -1;
    }
  }
  memset(encodebuf + d, 0, p);
  send_crypt->encrypt((uint8_t *)v.iov_base + HEADER_LEN, encodebuf,
                      d + p, hdr.nonce(), HEADER_LEN);
  if (evbuffer_commit_space(block, &v, 1)) {
    log_warn(conn, "failed to commit block buffer");
    evbuffer_free(block);
    return -1;
  }

  char fallbackbuf[4];
  log_debug(conn, "transmitting block %u <d=%lu p=%lu f=%s>",
            hdr.seqno(), (unsigned long)hdr.dlen(), (unsigned long)hdr.plen(),
            opname(hdr.opcode(), fallbackbuf));

  if (config->trace_packets)
    fprintf(stderr, "T:%.4f: ckt %u <ntp %u outq %lu>: send %lu <d=%lu p=%lu f=%s>\n",
            log_get_timestamp(), this->serial,
            this->recv_queue.window(),
              (unsigned long)evbuffer_get_length(bufferevent_get_input(this->up_buffer)),
            (unsigned long)hdr.seqno(),
            (unsigned long)hdr.dlen(),
            (unsigned long)hdr.plen(),
            opname(hdr.opcode(), fallbackbuf));

  if (conn->send(block)) {
    evbuffer_free(block);
    return -1;
  }

  evbuffer_free(block);
  evbuffer_drain(payload, d);

  send_seq++;
  if (f == op_FIN || f == op_STEG_FIN) {
    sent_fin = true;
    read_eof = true;
  }
  if ((f == op_DAT && d > 0) || 
      (f == op_STEG0 && d > 0) ||
      f == op_FIN ||
      f == op_STEG_FIN)
    // We are making forward progress if we are _either_ sending or
    // receiving data.
    dead_cycles = 0;
  return 0;
}

// N.B. 'desired' is the desired size of the _data section_, and
// 'blocksize' on output is the size to make the _entire block_.
chop_conn_t *
chop_circuit_t::pick_connection(size_t desired, size_t *blocksize)
{
  size_t maxbelow = 0;
  size_t minabove = MAX_BLOCK_SIZE + 1;
  chop_conn_t *targbelow = 0;
  chop_conn_t *targabove = 0;

  if (desired > SECTION_LEN)
    desired = SECTION_LEN;

  desired += MIN_BLOCK_SIZE;

  // If we have any data to transmit, ensure we do not send a block
  // that contains no data at all.
  size_t lo = MIN_BLOCK_SIZE + (desired == MIN_BLOCK_SIZE ? 0 : 1);

  log_debug(this, "target block size %lu bytes", (unsigned long)desired);

  // Find the best fit for the desired transmission from all the
  // outbound connections' transmit rooms.
  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;

    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!conn->steg) {
      log_debug(conn, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!conn->connected) {
      log_debug(conn, "offers 0 bytes (not connected)");
      continue;
    }

    size_t shake = conn->sent_handshake ? 0 : HANDSHAKE_LEN;
    size_t room = conn->steg->transmit_room(desired + shake, lo + shake,
                                            MAX_BLOCK_SIZE + shake);
    if (room == 0) {
      log_debug(conn, "offers 0 bytes (%s)",
                conn->steg->cfg()->name());
      continue;
    }

    if (room < lo + shake || room >= MAX_BLOCK_SIZE + shake)
      log_abort(conn, "steg size request (%lu) out of range [%lu, %lu]",
                (unsigned long)room,
                (unsigned long)(lo + shake),
                (unsigned long)(MAX_BLOCK_SIZE + shake));

    log_debug(conn, "offers %lu bytes (%s)", (unsigned long)room,
              conn->steg->cfg()->name());

    if (room >= desired + shake) {
      if (room < minabove) {
        minabove = room;
        targabove = conn;
      }
    } else {
      if (room > maxbelow) {
        maxbelow = room;
        targbelow = conn;
      }
    }
  }

  log_debug(this, "minabove %lu for <%u.%u> maxbelow %lu for <%u.%u>",
            (unsigned long)minabove, serial, targabove ? targabove->serial :0,
            (unsigned long)maxbelow, serial, targbelow ? targbelow->serial :0);

  // If we have a connection that can take all the data, use it.
  // Otherwise, use the connection that can take as much of the data
  // as possible.  As a special case, if no connection can take data,
  // targbelow, targabove, maxbelow, and minabove will all still have
  // their initial values, so we'll return NULL and set blocksize to 0,
  // which callers know how to handle.
  if (targabove) {
    *blocksize = minabove;
    return targabove;
  } else {
    *blocksize = maxbelow;
    return targbelow;
  }
}

chop_conn_t* chop_circuit_t::check_for_steg_protocol_data()
{
  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;

    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!conn->steg) {
      log_debug(conn, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!conn->connected) {
      log_debug(conn, "offers 0 bytes (not connected)");
      continue;
    }

    //Now we check if the protocol_data has any data
    if (evbuffer_get_length(conn->steg->cfg()->protocol_data_out))
        return conn;

  }

  //nothing to send
  return NULL;

}


int
chop_circuit_t::process_queue()
{
  reassembly_elt blk;
  unsigned int count = 0;
  bool pending_fin = false;
  bool pending_error = false;
  bool sent_error = false;
  while ((blk = recv_queue.remove_next()).data) {
    switch (blk.op) {
    case op_FIN:
      if (received_fin) {
        log_info(this, "protocol error: duplicate FIN");
        pending_error = true;
        break;
      }
      log_debug(this, "received FIN");
      pending_fin = true;
      // fall through - block may have data
    case op_DAT:
      if (evbuffer_get_length(blk.data)) {
        if (received_fin) {
          log_info(this, "protocol error: data after FIN");
          pending_error = true;
        } else {
          // We are making forward progress if we are _either_ sending or
          // receiving data.
          dead_cycles = 0;
          if (evbuffer_add_buffer(bufferevent_get_output(up_buffer),
                                  blk.data)) {
            log_warn(this, "buffer transfer failure");
            pending_error = true;
          }
        }
      }
      break;

    case op_STEG_FIN:
      if (received_fin) {
        log_info(this, "protocol error: duplicate FIN");
        pending_error = true;
        break;
      }
      log_debug(this, "received (STEG) FIN");
      pending_fin = true;
      // fall through - block may have data
    case op_STEG0:
      //write it to steg protocol data
      //FIX ME I need to check if the conn is still 
      //alive/valid
      if (evbuffer_get_length(blk.data))
        evbuffer_add_buffer(((chop_conn_t*)blk.conn)->steg->cfg()->protocol_data_in, blk.data);
      
      //now ask the steg to process the data
      ((chop_conn_t*)blk.conn)->steg->cfg()->process_protocol_data();
      //if steg needs to reply to the data it writes it to the same 
      //buffer and we need to send them
      if (evbuffer_get_length(((chop_conn_t*)blk.conn)->steg->cfg()->protocol_data_out))
          send();
      break;
      
    case op_RST:
      log_info(this, "received RST; disconnecting circuit");
      circuit_recv_eof(this);
      pending_error = true;
      break;

    default:
      char fallbackbuf[4];
      log_warn(this, "protocol error: unsupported block opcode %s",
               opname(blk.op, fallbackbuf));
      pending_error = true;
      break;
    }

    evbuffer_free(blk.data);

    if (pending_fin && !received_fin) {
      circuit_recv_eof(this);
      received_fin = true;
    }
    if (pending_error && !sent_error) {
      // there's no point sending an RST in response to an RST or a
      // duplicate FIN
      if (blk.op != op_RST && blk.op != op_FIN && blk.op != op_STEG_FIN)
        send_special(op_RST, 0);
      sent_error = true;
    }
    count++;
  }

  log_debug(this, "processed %u blocks", count);
  if (sent_error)
    return -1;

  // It may have become possible to send queued data or a FIN.
  if (evbuffer_get_length(bufferevent_get_input(up_buffer))
      || (upstream_eof && !sent_fin))
    return send();

  return check_for_eof();
}

int
chop_circuit_t::check_for_eof()
{
  // If we're at EOF both ways, close all connections, sending first
  // if necessary.
  if (sent_fin && received_fin) {
    log_debug(this, "sent and received FIN");
    circuit_disarm_flush_timer(this);
    for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
         i != downstreams.end(); i++) {
      chop_conn_t *conn = *i;
      if (conn->must_send_p())
        conn->send();
      conn_send_eof(conn);
    }
  }

  // If we're the client we have to keep trying to talk as long as we
  // haven't both sent and received a FIN, or we might deadlock.
  else if (config->mode != LSN_SIMPLE_SERVER) {
    log_debug(this, "client arming flush timer%s%s",
              sent_fin ? " (sent FIN)" : "",
              received_fin ? " (received FIN)": "");
    circuit_arm_flush_timer(this, flush_interval());
  }

  return 0;
}

// Connection methods

conn_t *
chop_config_t::conn_create(size_t index)
{
  chop_conn_t *conn = new chop_conn_t;
  conn->config = this;
  conn->steg = steg_targets.at(index)->steg_create(conn);
  if (!conn->steg) {
    free(conn);
    return 0;
  }

  conn->recv_pending = evbuffer_new();
  return conn;
}

chop_conn_t::chop_conn_t()
{
}

chop_conn_t::~chop_conn_t()
{
  if (this->must_send_timer)
    event_free(this->must_send_timer);
  if (steg)
    delete steg;
  evbuffer_free(recv_pending);
}

void
chop_conn_t::close()
{
  if (this->must_send_timer)
    event_del(this->must_send_timer);

  if (upstream)
    upstream->drop_downstream(this);

  conn_t::close();
}

circuit_t *
chop_conn_t::circuit() const
{
  return upstream;
}

int
chop_conn_t::maybe_open_upstream()
{
  // We can't open the upstream until we have a circuit ID.
  return 0;
}

int
chop_conn_t::send(struct evbuffer *block)
{
  if (!sent_handshake && config->mode != LSN_SIMPLE_SERVER) {
    if (!upstream || upstream->circuit_id == 0)
      log_abort(this, "handshake: can't happen: up%c cid=%u",
                upstream ? '+' : '-',
                upstream ? upstream->circuit_id : 0);
    if (evbuffer_prepend(block, (void *)&upstream->circuit_id,
                         HANDSHAKE_LEN)) {
      log_warn(this, "failed to prepend handshake to first block");
      return -1;
    }
  }

  if (steg->transmit(block)) {
    log_warn(this, "failed to transmit block");
    return -1;
  }
  sent_handshake = true;
  if (must_send_timer)
    evtimer_del(must_send_timer);
  return 0;
}

int
chop_conn_t::handshake()
{
  // The actual handshake is generated in chop_conn_t::send so that it
  // can be merged with a block if possible; however, we use this hook
  // to ensure that the client sends _something_ ASAP after each new
  // connection, because the server can't forward traffic, or even
  // open a socket to its own upstream, until it knows which circuit
  // to associate this new connection with.  Note that in some cases
  // it's possible for us to have _already_ sent something on this
  // connection by the time we get called back!  Don't do it twice.
  if (config->mode != LSN_SIMPLE_SERVER && !sent_handshake)
    send();
  return 0;
}

int
chop_conn_t::recv_handshake()
{
  log_assert(!upstream);
  log_assert(config->mode == LSN_SIMPLE_SERVER);

  uint32_t circuit_id;
  if (evbuffer_remove(recv_pending, (void *)&circuit_id,
                      sizeof circuit_id) != sizeof circuit_id)
    return -1;

  chop_circuit_table::value_type in(circuit_id, (chop_circuit_t *)0);
  std::pair<chop_circuit_table::iterator, bool> out
    = this->config->circuits.insert(in);
  chop_circuit_t *ck;

  if (!out.second) { // element already exists
    if (!out.first->second) {
      log_debug(this, "stale circuit");
      return 0;
    }
    ck = out.first->second;
    log_debug(this, "found circuit to %s", ck->up_peer);
  } else {
    ck = dynamic_cast<chop_circuit_t *>(circuit_create(this->config, 0));
    if (!ck) {
      log_warn(this, "failed to create new circuit");
      return -1;
    }
    if (circuit_open_upstream(ck)) {
      log_warn(this, "failed to begin upstream connection");
      ck->close();
      return -1;
    }
    log_debug(this, "created new circuit to %s", ck->up_peer);
    ck->circuit_id = circuit_id;
    out.first->second = ck;
  }

  ck->add_downstream(this);
  return 0;
}

int
chop_conn_t::recv()
{
  if (steg->receive(recv_pending))
    return -1;

  // If that succeeded but did not copy anything into recv_pending,
  // wait for more data.
  if (evbuffer_get_length(recv_pending) == 0)
    return 0;

  if (!upstream) {
    if (config->mode != LSN_SIMPLE_SERVER) {
      // We're the client.  Client connections start out attached to a
      // circuit; therefore this is a server-to-client message that
      // crossed with the teardown of the circuit it belonged to, and
      // we don't have the decryption keys for it anymore.
      // By construction it must be chaff, so just throw it away.
      log_debug(this, "discarding chaff after circuit closed");
      log_assert(!must_send_p());
      conn_do_flush(this);
      return 0;
    }

    // We're the server. Try to receive a handshake.
    if (recv_handshake())
      return -1;

    // If we get here and ->upstream is not set, this is a connection
    // for a stale circuit: that is, a new connection made by the
    // client (to draw more data down from the server) that crossed
    // with a server-to-client FIN, the client-to-server FIN already
    // having been received and processed.  We no longer have the keys
    // to decrypt anything after the handshake, but it's either chaff
    // or a protocol error.  Either way, we can just drop the
    // connection, possibly sending a response if the cover protocol
    // requires one.
    if (!upstream) {
      if (must_send_p())
        send();
      conn_do_flush(this);
      return 0;
    }
  }

  log_debug(this, "circuit to %s", upstream->up_peer);
  for (;;) {
    size_t avail = evbuffer_get_length(recv_pending);
    if (avail == 0)
      break;

    log_debug(this, "%lu bytes available", (unsigned long)avail);
    if (avail < MIN_BLOCK_SIZE) {
      log_debug(this, "incomplete block framing");
      break;
    }

    header hdr(recv_pending, *upstream->recv_hdr_crypt);
    if (!hdr.valid(upstream->recv_queue.window())) {
      const uint8_t *c = hdr.cleartext();
      char fallbackbuf[4];
      log_info(this, "invalid block header: "
               "%lu|%lu|%lu|%s|%02x%02x%02x%02x%02x%02x%02x",
               (unsigned long)hdr.seqno(),
               (unsigned long)hdr.dlen(),
               (unsigned long)hdr.plen(),
               opname(hdr.opcode(), fallbackbuf),
               c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

      if (config->trace_packets)
        fprintf(stderr, "T:%.4f: ckt %u <ntp %u outq %lu>: recv-error "
                "%lu <d=%lu p=%lu f=%s c=%02x%02x%02x%02x%02x%02x%02x>\n",
                log_get_timestamp(), upstream->serial,
                upstream->recv_queue.window(),
                (unsigned long)evbuffer_get_length(bufferevent_get_input(upstream->up_buffer)),
                (unsigned long)hdr.seqno(),
                (unsigned long)hdr.dlen(),
                (unsigned long)hdr.plen(),
                opname(hdr.opcode(), fallbackbuf),
                c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

      return -1;
    }
    if (avail < hdr.total_len()) {
      log_debug(this, "incomplete block (need %lu bytes)",
                (unsigned long)hdr.total_len());
      break;
    }

    uint8_t decodebuf[MAX_BLOCK_SIZE];
    if (evbuffer_drain(recv_pending, HEADER_LEN) ||
        evbuffer_remove(recv_pending, decodebuf, hdr.total_len() - HEADER_LEN)
        != (ssize_t)(hdr.total_len() - HEADER_LEN)) {
      log_warn(this, "failed to copy block to decode buffer");
      return -1;
    }
    if (upstream->recv_crypt->decrypt(decodebuf,
                                      decodebuf, hdr.total_len() - HEADER_LEN,
                                      hdr.nonce(), HEADER_LEN)) {
      log_info("MAC verification failure");
      return -1;
    }

    char fallbackbuf[4];
    log_debug(this, "receiving block %u <d=%lu p=%lu f=%s>",
              hdr.seqno(), (unsigned long)hdr.dlen(), (unsigned long)hdr.plen(),
              opname(hdr.opcode(), fallbackbuf));

    if (config->trace_packets)
      {
        fprintf(stderr, "T:%.4f: ckt %u <ntp %u outq %lu>: recv %lu <d=%lu p=%lu f=%s>\n",
              log_get_timestamp(), upstream->serial,
              upstream->recv_queue.window(),
              (unsigned long)evbuffer_get_length(bufferevent_get_input(upstream->up_buffer)),
              (unsigned long)hdr.seqno(),
              (unsigned long)hdr.dlen(),
              (unsigned long)hdr.plen(),
              opname(hdr.opcode(), fallbackbuf));
         // vmon: I need the content of the packet as well.
        if (hdr.dlen())
          {
            char* data_4_log =  new char[hdr.dlen() + 1];
            memcpy(data_4_log, decodebuf, hdr.dlen());
            data_4_log[hdr.dlen()] = '\0';
            log_info("Data received: %s",  data_4_log);
            
          }
      }
    
    evbuffer *data = evbuffer_new();
    if (!data || (hdr.dlen() && evbuffer_add(data, decodebuf, hdr.dlen()))) {
      log_warn(this, "failed to extract data from decode buffer");
      evbuffer_free(data);
      return -1;
    }

    if (!upstream->recv_queue.insert(hdr.seqno(), hdr.opcode(), data, this))
      return -1; // insert() logs an error
  }

  return upstream->process_queue();
}

int
chop_conn_t::recv_eof()
{
  // Consume any not-yet-processed incoming data.  It's possible for
  // us to get here before we've processed _any_ data -- including the
  // handshake! -- from a new connection, so we have to do this before
  // we look at ->upstream.  */
  if (evbuffer_get_length(inbound()) > 0) {
    if (recv())
      return -1;
    // If there's anything left in the buffer at this point, it's a
    // protocol error.
    if (evbuffer_get_length(inbound()) > 0)
      return -1;
  }

  // We should only drop the connection from the circuit if we're no
  // longer sending covert data in the opposite direction _and_ the
  // cover protocol does not need us to send a reply (i.e. the
  // must_send_timer is not pending).
  if (upstream && (upstream->sent_fin || no_more_transmissions) &&
      !must_send_p() && evbuffer_get_length(outbound()) == 0)
    upstream->drop_downstream(this);

  return 0;
}

void
chop_conn_t::expect_close()
{
  read_eof = true;
}

void
chop_conn_t::cease_transmission()
{
  no_more_transmissions = true;
  if (must_send_timer)
    evtimer_del(must_send_timer);
  conn_do_flush(this);
}

void
chop_conn_t::transmit_soon(unsigned long milliseconds)
{
  struct timeval tv;

  log_debug(this, "must send within %lu milliseconds", milliseconds);

  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  if (!must_send_timer)
    must_send_timer = evtimer_new(config->base, must_send_timeout, this);
  evtimer_add(must_send_timer, &tv);
}

void
chop_conn_t::send()
{
  if (must_send_timer)
    evtimer_del(must_send_timer);

  if (!steg) {
    log_warn(this, "send() called with no steg module available");
    conn_do_flush(this);
    return;
  }

  // When this happens, we must send _even if_ we have no upstream to
  // provide us with data.  For instance, to preserve the cover
  // protocol, we must send an HTTP reply to each HTTP query that
  // comes in for a stale circuit.
  if (upstream) {
    log_debug(this, "must send");
    if (upstream->send_targeted(this)) {
      upstream->drop_downstream(this);
      conn_do_flush(this);
    }

  } else {
    log_debug(this, "must send (no upstream)");

    size_t room = steg->transmit_room(MIN_BLOCK_SIZE, MIN_BLOCK_SIZE,
                                      MAX_BLOCK_SIZE);
    if (room < MIN_BLOCK_SIZE || room >= MAX_BLOCK_SIZE)
      log_abort(this, "steg size request (%lu) out of range [%lu, %lu]",
                (unsigned long)room,
                (unsigned long)MIN_BLOCK_SIZE,
                (unsigned long)MAX_BLOCK_SIZE);

    // Since we have no upstream, we can't encrypt anything; instead,
    // generate random bytes and feed them straight to steg_transmit.
    struct evbuffer *chaff = evbuffer_new();
    struct evbuffer_iovec v;
    if (!chaff || evbuffer_reserve_space(chaff, room, &v, 1) != 1 ||
        v.iov_len < room) {
      log_warn(this, "memory allocation failed");
      if (chaff)
        evbuffer_free(chaff);
      conn_do_flush(this);
      return;
    }
    v.iov_len = room;
    rng_bytes((uint8_t *)v.iov_base, room);
    if (evbuffer_commit_space(chaff, &v, 1)) {
      log_warn(this, "evbuffer_commit_space failed");
      if (chaff)
        evbuffer_free(chaff);
      conn_do_flush(this);
      return;
    }

    if (steg->transmit(chaff))
      conn_do_flush(this);

    evbuffer_free(chaff);
  }
}

bool
chop_conn_t::must_send_p() const
{
  return must_send_timer && evtimer_pending(must_send_timer, 0);
}

/* static */ void
chop_conn_t::must_send_timeout(evutil_socket_t, short, void *arg)
{
  static_cast<chop_conn_t *>(arg)->send();
}

PROTO_DEFINE_MODULE(chop);

// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
