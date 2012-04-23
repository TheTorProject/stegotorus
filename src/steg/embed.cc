/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include "rng.h"

#include <errno.h>
#include <event2/buffer.h>
#include <vector>

using std::vector;

namespace {
  struct trace_t {
    vector<short> pkt_sizes;  // packet sizes (positive = client->server)
    vector<int> pkt_times;    // packet inter-arrival times
  };

  struct embed_steg_config_t : steg_config_t {
    bool is_clientside;
    vector<trace_t> traces;

    STEG_CONFIG_DECLARE_METHODS(embed);

    size_t get_random_trace() const;
  };

  struct embed_steg_t : steg_t {
    embed_steg_config_t *config;
    conn_t *conn;

    int cur_idx;           // current trace index
    trace_t *cur;             // current trace
    int cur_pkt;           // current packet in the trace
    struct timeval last_pkt;  // time at which last packet was sent/received

    embed_steg_t(embed_steg_config_t *cf, conn_t *cn);

    STEG_DECLARE_METHODS(embed);

    bool advance_packet();
    short get_pkt_size();
    bool is_outgoing();
    int get_pkt_time();
    bool is_finished();
  };
}

STEG_DEFINE_MODULE(embed);

static int
millis_since(struct timeval *last)
{
  struct timeval cur;
  int diff = 0;
  gettimeofday(&cur, NULL);

  diff += (cur.tv_sec - last->tv_sec) * 1000;
  diff += (cur.tv_usec - last->tv_usec) / 1000;
  return diff;
}

embed_steg_config_t::embed_steg_config_t(config_t *cfg)
  : steg_config_t(cfg),
    is_clientside(cfg->mode != LSN_SIMPLE_SERVER)
{
  // read in traces to use for connections
  FILE *trace_file = fopen("traces/embed.txt", "r");
  if (!trace_file)
    log_abort("opening traces/embed.txt: %s", strerror(errno));

  int num_traces;
  if (fscanf(trace_file, "%d", &num_traces) < 1)
    log_abort("couldn't read number of traces");

  traces.resize(num_traces);

  for (vector<trace_t>::iterator p = traces.begin(); p != traces.end(); ++p) {
    int num_pkt;
    if (fscanf(trace_file, "%d", &num_pkt) < 1)
      log_abort("couldn't read number of packets in trace %ld",
                p - traces.begin());

    p->pkt_sizes.resize(num_pkt);
    p->pkt_times.resize(num_pkt);
    for (int i = 0; i < num_pkt; i++)
      if (fscanf(trace_file, "%hd %d", &p->pkt_sizes[i], &p->pkt_times[i]) < 1)
        log_abort("couldn't read trace entry %ld/%d",
                  p - traces.begin(), i);
  }

  log_debug("read %d traces", num_traces);
}

embed_steg_config_t::~embed_steg_config_t()
{
}

steg_t *
embed_steg_config_t::steg_create(conn_t *conn)
{
  return new embed_steg_t(this, conn);
}

size_t
embed_steg_config_t::get_random_trace() const
{
  return rng_int(traces.size());
}

bool
embed_steg_t::advance_packet()
{
  cur_pkt++;
  return cur_pkt == int(cur->pkt_sizes.size());
}

short
embed_steg_t::get_pkt_size()
{
  return abs(cur->pkt_sizes[cur_pkt]);
}

bool
embed_steg_t::is_outgoing()
{
  return (cur->pkt_sizes[cur_pkt] < 0) ^ config->is_clientside;
}

int
embed_steg_t::get_pkt_time()
{
  return cur->pkt_times[cur_pkt];
}

bool
embed_steg_t::is_finished()
{
  if (cur_idx == -1) return true;
  return cur_pkt >= int(cur->pkt_sizes.size());
}

embed_steg_t::embed_steg_t(embed_steg_config_t *cf, conn_t *cn)
  : config(cf), conn(cn)
{
  cur_idx = -1;
  if (config->is_clientside) {
    cur_idx = config->get_random_trace();
    cur = &config->traces[cur_idx];
    cur_pkt = 0;
  }
  gettimeofday(&last_pkt, NULL);
}

embed_steg_t::~embed_steg_t()
{
}

steg_config_t *
embed_steg_t::cfg()
{
  return config;
}

size_t
embed_steg_t::transmit_room(size_t, size_t lo, size_t hi)
{
  if (is_finished() || !is_outgoing()) return 0;

  int time_diff = millis_since(&last_pkt);
  if (get_pkt_time() > time_diff+10) return 0;

  // 2 bytes for data length, 4 bytes for the index of a new trace
  size_t room = get_pkt_size() - 2;
  if (cur_pkt == 0) room -= 4;

  if (room < lo) room = lo;
  if (room > hi) room = hi;
  return room;
}

int
embed_steg_t::transmit(struct evbuffer *source)
{
  struct evbuffer *dest = conn->outbound();
  short src_len = evbuffer_get_length(source);
  short pkt_size = get_pkt_size();
  short used = src_len + 2;

  // starting a new trace, send the index
  if (cur_pkt == 0) {
    if (evbuffer_add(dest, &cur_idx, 4) == -1) return -1;
    used += 4;
    log_debug("sending trace %d", cur_idx);
  }

  log_debug("sending packet %d of trace %d", cur_pkt, cur_idx);

  // add the data length and data to the dest buffer
  if (evbuffer_add(dest, &src_len, 2) == -1) return -1;
  if (evbuffer_add_buffer(dest, source) == -1) return -1;
  log_debug("sending data with length %d", src_len);

  // if there is more space in the packet, pad it
  if (pkt_size > used) {
    size_t padding = pkt_size - used;
    unsigned char zero[padding];
    memset(zero, 0, padding);
    evbuffer_add(dest, zero, padding);
  }

  // check if this trace is finished and whether we need to send again
  if (advance_packet()) {
    log_debug("send finished trace");
    conn->cease_transmission();
  } else if (is_outgoing()) {
    log_debug("sending again in %d ms", get_pkt_time());
    conn->transmit_soon(get_pkt_time());
  }

  // update last time
  gettimeofday(&last_pkt, NULL);
  return 0;
}

int
embed_steg_t::receive(struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();
  short src_len = evbuffer_get_length(source);
  short pkt_size = 0;

  log_debug("receiving buffer of length %d", src_len);

  // if we are receiving the first packet of the trace, read the index
  if (cur_idx == -1) {
    if (evbuffer_remove(source, &cur_idx, 4) != 4) return -1;
    cur = &config->traces[cur_idx];
    cur_pkt = 0;
    pkt_size += 4;

    log_debug("received first packet of trace %d", cur_idx);
  }

  // keep reading data and padding from the source, advancing the packet
  // in the trace when we have read enough bytes
  while (1) {
    // the next full packet is not in the source buffer yet
    int exp_pkt_size = get_pkt_size();
    if (src_len < exp_pkt_size) break;

    // read data
    short data_len;
    if (evbuffer_remove(source, &data_len, 2) != 2) return -1;
    if (data_len > 0) {
      if (evbuffer_remove_buffer(source, dest, data_len) != data_len) {
return -1;
      }
    }
    pkt_size += data_len + 2;

    // read padding
    if (exp_pkt_size > pkt_size) {
      size_t padding = exp_pkt_size - pkt_size;
      if (evbuffer_drain(source, padding) == -1) return -1;
    }

    src_len -= exp_pkt_size;
    pkt_size = 0;

    log_debug("received packet %d of trace %d",
              cur_pkt, cur_idx);

    // advance packet; if done with trace, sender should close connection
    if (advance_packet()) {
      conn->cease_transmission();
      conn->expect_close();
      log_debug("received last packet in trace");
      return 0;
    }
  }

  if (is_outgoing()) {
    log_debug("preparing to send in %d ms", get_pkt_time());
    conn->transmit_soon(get_pkt_time());
  }

  log_debug("remaining source length: %d", src_len);

  // update last time
  gettimeofday(&last_pkt, NULL);
  return 0;
}
