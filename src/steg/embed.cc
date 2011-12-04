#include "util.h"
#include "connections.h"
#include "steg.h"

#include <event2/buffer.h>
#include <event2/event.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

typedef struct trace_t {
  int num_pkt;              // number of packets in trace
  short *pkt_sizes;         // packet sizes (positive = client->server)
  int *pkt_times;           // packet inter-arrival times
} trace_t;

namespace {
  struct embed : steg_t {
    int cur_idx;              // current trace index
    trace_t *cur;             // current trace
    int cur_pkt;              // current packet in the trace
    struct timeval last_pkt;  // time at which last packet was sent/received

    STEG_DECLARE_METHODS(embed);

    bool advance_packet();
    short get_pkt_size();
    bool is_outgoing();
    int get_pkt_time();
    bool is_finished();
  };
}

static int embed_init = 0;      // whether traces are initialized
static int embed_num_traces;    // number of traces
static trace_t *embed_traces;   // global array of all traces

STEG_DEFINE_MODULE(embed, 1024, 1024, 1, 1);

int millis_since(struct timeval *last) {
  struct timeval cur;
  int diff = 0;
  gettimeofday(&cur, NULL);

  diff += (cur.tv_sec - last->tv_sec) * 1000;
  diff += (cur.tv_usec - last->tv_usec) / 1000;
  return diff;
}

void init_embed_traces() {
  // read in traces to use for connections
  FILE *trace_file = fopen("traces/embed.txt", "r");
  fscanf(trace_file, "%d", &embed_num_traces);
  embed_traces = (trace_t *)xmalloc(sizeof(trace_t) * embed_num_traces);
  for (int i = 0; i < embed_num_traces; i++) {
    int num_pkt;
    fscanf(trace_file, "%d", &num_pkt);
    embed_traces[i].num_pkt = num_pkt;
    embed_traces[i].pkt_sizes = (short *)xmalloc(sizeof(short) * num_pkt);
    embed_traces[i].pkt_times = (int *)xmalloc(sizeof(int) * num_pkt);
    for (int j = 0; j < embed_traces[i].num_pkt; j++) {
      fscanf(trace_file, "%hd %d",
	     &embed_traces[i].pkt_sizes[j],
	     &embed_traces[i].pkt_times[j]);
    }
  }
  log_debug("read %d traces to use", embed_num_traces);

  srand(time(NULL));
  embed_init = 1;
}

int get_random_trace() {
  return rand() % embed_num_traces;
}

bool embed::advance_packet() {
  cur_pkt++;
  return cur_pkt == cur->num_pkt;
}

short embed::get_pkt_size() {
  return abs(cur->pkt_sizes[cur_pkt]);
}

bool embed::is_outgoing() {
  return (cur->pkt_sizes[cur_pkt] < 0) ^ is_clientside;
}

int embed::get_pkt_time() {
  return cur->pkt_times[cur_pkt];
}

bool embed::is_finished() {
  if (cur_idx == -1) return true;
  return cur_pkt >= cur->num_pkt;
}

embed::embed() {
  if (!embed_init) init_embed_traces();
  cur_idx = -1;
  gettimeofday(&last_pkt, NULL);
}

embed::~embed() { }

bool embed::detect(conn_t * /* conn */) {
  return 1;
}

size_t embed::transmit_room(conn_t * /* conn */) {
  if (cur_idx == -1 && is_clientside) {
    cur_idx = get_random_trace();
    cur = &embed_traces[cur_idx];
    cur_pkt = 0;
  }

  int time_diff = millis_since(&last_pkt);
  size_t room;

  if (is_finished() || !is_outgoing()) return 0;
  if (get_pkt_time() > time_diff+10) return 0;

  // 24 bytes for chop header, 2 bytes for data length
  // 4 bytes for the index of a new trace
  room = get_pkt_size() - 26;
  if (cur_pkt == 0) {
    room -= 4;
  }
  return room;
}

int embed::transmit(struct evbuffer *source, conn_t *conn) {
  struct evbuffer *dest = conn_get_outbound(conn);
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
    conn_close_after_transmit(conn);
  } else if (is_outgoing()) {
    log_debug("sending again in %d ms", get_pkt_time());
    conn_transmit_soon(conn, get_pkt_time());
  }

  // update last time
  gettimeofday(&last_pkt, NULL);
  return 0;
}

int embed::receive(conn_t *conn, struct evbuffer *dest) {
  struct evbuffer *source = conn_get_inbound(conn);
  short src_len = evbuffer_get_length(source);
  short pkt_size = 0;

  log_debug("receiving buffer of length %d", src_len);
  
  // if we are receiving the first packet of the trace, read the index
  if (cur_idx == -1) {
    if (evbuffer_remove(source, &cur_idx, 4) != 4) return -1;
    cur = &embed_traces[cur_idx];
    cur_pkt = 0;
    pkt_size += 4;

    log_debug("detected trace %d", cur_idx);
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
      conn_cease_transmission(conn);
      conn_expect_close(conn);
      log_debug("received last packet in trace");
      return 0;
    }
  }

  if (is_outgoing()) {
    log_debug("preparing to send in %d ms", get_pkt_time());
    conn_transmit_soon(conn, get_pkt_time());
  }

  log_debug("remaining source length: %d", src_len);

  // update last time
  gettimeofday(&last_pkt, NULL);
  return 0;
}
