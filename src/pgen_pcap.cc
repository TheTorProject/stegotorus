/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "pgen.h"
#include "compression.h"

#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <pcap/pcap.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define NUM_FLOWS 1000
#define NUM_LISTS 1000

#define CONN_DATA_REQUEST 1  /* payload packet sent by client */
#define CONN_DATA_REPLY 2  /* payload packet sent by server */

#define RECV_MTU 64000
// #define PKT_MTU 1500
#define MAX_CHAIN_LEN 4000

#define MSG_INSERTED 1
#define MSG_INVALID 0
#define MSG_SEQ_WRAP -2
#define MSG_DUPLICATE -3
#define CHAIN_TOO_LONG -4
#define MSG_OVERLAP -5
#define CHAIN_HAS_GAPS_OVERLAPS -6
#define CHAIN_EMPTY -7

struct msg {
  uint8_t *buf;
  uint16_t len;
  uint32_t seqno;
  msg *next_msg;
};

struct flow {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t sport;
  uint16_t dport;
  uint8_t flags;
  uint8_t proto;
  struct timeval change_time;
  int sockfd;
  flow *next_flow;
  msg *msg_buf_chain;
  int chain_len;
  int msg_len_so_far;
  int dir;           /* data request or data reply */
  uint32_t ack_so_far;  /* what's acknowledged by other end so far */
};

static flow *flows[NUM_LISTS];
static pcap_t *descr;
static int dir_flag = 0;
static char *bp_filter;
static char errbuf[PCAP_ERRBUF_SIZE];
static struct bpf_program fp;
static uint32_t netp;
static const char *argv0;

#define RECV_MTU 64000
#define PORT_HTTP 80

static FILE *client_file;
static FILE *server_file;

static void ATTR_NORETURN
usage()
{
  fprintf(stderr, "Usage: %s [-d dumpdir] [-r dumpfile] \"bpf filter\"\n",
          argv0);
  exit(1);
}

static void ATTR_NORETURN
terminate(int)
{
  struct pcap_stat ps;
  if (pcap_stats(descr, &ps) < 0) {
    fputs("err: pcap stats not supported?\n", stderr);
    exit(1);
  }

  printf("packets rcvd: %u, packets dropped: %u, interface drops: %u\n",
         ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
  exit(1);
}

static void
free_msg_chain(flow *f)
{
  msg *m = f->msg_buf_chain;

  while (m && f->chain_len > 0) {
    msg *n = m->next_msg;
    free(m);
    m = n;
  }

  f->chain_len = 0;
  f->msg_len_so_far = 0;
  f->msg_buf_chain = 0;
}

static bool
has_chain_gaps(flow *f)
{
  msg *m = f->msg_buf_chain;

  while (m) {
    if (!m->next_msg)
      return false;

    if (m->seqno + m->len < m->next_msg->seqno) {
      fprintf(stderr, "gap seqnos: %u %u %u %d\n",
              m->seqno, m->len, m->next_msg->seqno, f->dport);
      return true;
    }

    if (m->seqno + m->len  > m->next_msg-> seqno) {
      fprintf(stderr, "overlap seqnos: %u %u %u\n",
              m->seqno, m->len, m->next_msg->seqno);
      return true;
    }
    m = m->next_msg;
  }

  return false;
}

static int
write_inflate_msg(flow *f, FILE *file, pentry_header *ph)
{
  msg *m = f->msg_buf_chain;
  uint8_t *buf;
  int pos = 0;
  uint8_t *outbuf;
  int outlen;

  uint8_t *hdr_end;
  uint8_t *hdr;
  int hdrlen;

  if (!f->msg_buf_chain)
    return CHAIN_EMPTY;

  if (strstr((char*) m->buf, "Transfer-Encoding: chunked"))
    // we don't handle this yet....need a loop to unzip chunks individually...
    return MSG_INVALID;

  hdr_end = (uint8_t*) strstr((char*) m->buf, "\r\n\r\n");
  if (!hdr_end) {
    fprintf(stderr, "hdr too long?? \n");
    return MSG_INVALID;
  }

  hdr_end += 4;
  hdrlen = hdr_end - m->buf;
  hdr = (uint8_t *) xmemdup(m->buf, hdrlen);

  buf = (uint8_t *) xmalloc(f->msg_len_so_far);
  outbuf = (uint8_t *) xmalloc(f->msg_len_so_far * 20);

  pos = 0;

  if (!m)
    return  CHAIN_EMPTY;

  memcpy(buf, hdr_end, m->len - hdrlen);
  pos += m->len - hdrlen;
  m = m->next_msg;

  while (m) {
    memcpy(buf+pos, m->buf, m->len);
    pos += m->len;
    m = m->next_msg;
  }

  outlen = decompress(buf, f->msg_len_so_far - hdrlen,
                      outbuf, f->msg_len_so_far*20);

  if (outlen < 0) {
    fprintf(stderr, "unzip failed outlen = %d %d %d\n",
            outlen, pos, f->msg_len_so_far-hdrlen);
    return MSG_INVALID;
  }

  ph->length = htonl(outlen+hdrlen);
  if (fwrite(ph, sizeof(pentry_header), 1, file)!= sizeof(pentry_header))
    log_warn("error writing data: %s", strerror(errno));
  if (fwrite(hdr, hdrlen, 1, file)!= (unsigned int)hdrlen)
    log_warn("error writing data: %s", strerror(errno));
  if (fwrite(outbuf, outlen, 1, file)!= (unsigned int)outlen)
    log_warn("error writing data: %s", strerror(errno));
  free(buf);
  free(outbuf);
  free(hdr);
  return 1;
}

static int
write_msg_chains(flow *f, FILE *file, pentry_header *ph)
{
  msg *m = f->msg_buf_chain;
  int cnt = 0;

  if (has_chain_gaps(f))
    return CHAIN_HAS_GAPS_OVERLAPS;

  if (!m)
    return CHAIN_EMPTY;

  if (strstr((char*) m->buf, "200 OK") &&
      strstr((char*) m->buf, "Content-Encoding: gzip"))
    return write_inflate_msg(f, file, ph);

  if (fwrite(ph, sizeof(pentry_header), 1, file) != sizeof(pentry_header))
    log_warn("error writing data: %s", strerror(errno));

  while (m) {
    if (fwrite(m->buf, m->len, 1, file) != m->len)
      log_warn("error writing data: %s", strerror(errno));

    cnt += m->len;
    m = m->next_msg;
  }

  if (cnt != f->msg_len_so_far)
    fprintf(stderr, "something funky in writing message\n");
  return 1;
}

static bool
is_valid_http_request(flow *f)
{
  if (!f->msg_buf_chain) {
    fprintf(stderr, "is_valid_http_request: invalid chain %d\n", f->chain_len);
    return false;
  }

  if (!strncmp((char*) f->msg_buf_chain->buf, "GET", 3) ||
      !strncmp((char*) f->msg_buf_chain->buf, "POST", 4)) {
    msg *m = f->msg_buf_chain;
    while (m->next_msg)
      m = m->next_msg;

    if (m->buf[m->len-2] == '\r' && m->buf[m->len-1] == '\n') {
      return true;
    }
  }

  return false;
}

static int
add_msg_to_flow(flow *f, uint8_t *buf, uint seq, int len)
{
  if (len > RECV_MTU)
    return MSG_INVALID;

  if (f->chain_len >= MAX_CHAIN_LEN)
    return CHAIN_TOO_LONG;

  if (seq > seq + len)
    return MSG_SEQ_WRAP;

  msg *p = 0;
  msg *m = f->msg_buf_chain;

  if (!m) {
    m = (msg *)xzalloc(sizeof(msg));
    m->buf = (uint8_t *)xmalloc(len);
    memcpy(m->buf, buf, len);
    m->seqno = seq;
    f->chain_len = 1;
    f->msg_len_so_far += len;
    f->msg_buf_chain = m;
    m->len = len;
    return MSG_INSERTED;
  }

  while (m) {
    if (m->seqno == seq)
      return MSG_DUPLICATE;

    if (m->seqno < seq) {
      if (m->seqno > seq + len)
        return MSG_OVERLAP;
      p = m;
      m = m->next_msg;
      continue;
    }

    if (m->seqno < seq + len)
      return MSG_OVERLAP;

    msg *n;
    if (!p) {
      p = (msg *)xzalloc(sizeof(msg));
      p->buf = (uint8_t *)xmalloc(len);
      memcpy(p->buf, buf, len);
      p->seqno = seq;
      p->next_msg = m;
      f->chain_len++;
      f->msg_len_so_far += len;
      f->msg_buf_chain = p;
      p->len = len;
      return MSG_INSERTED;
    }

    n = (msg *)xzalloc(sizeof(msg));
    n->buf = (uint8_t *)xmemdup(buf, len);
    memcpy(n->buf, buf, len);
    n->seqno = seq;
    n->next_msg = m;
    p->next_msg = n;
    f->chain_len++;
    f->msg_len_so_far += len;
    n->len = len;
    return MSG_INSERTED;
  }

  m = (msg *)xzalloc(sizeof(msg));
  m->buf = (uint8_t *)xmemdup(buf, len);
  m->seqno = seq;
  p->next_msg = m;
  f->chain_len++;
  f->msg_len_so_far += len;
  m->len = len;
  return MSG_INSERTED;
}

static int
hash_flow(flow *f)
{
  return (f->src_ip + f->dst_ip + f->sport + f->dport) % NUM_LISTS;
}

static bool
flow_compare(flow *f1, flow *f2)
{
  return (f1->src_ip == f2->src_ip && f1->dst_ip == f2->dst_ip
          && f1->sport == f2->sport && f1->dport == f2->dport);
}

static flow *
add_to_flows(flow *f)
{
  int hval = hash_flow(f);

  flow *cflow = flows[hval];

  if (!cflow) {
    cflow = (flow *) xmalloc(sizeof(flow));
    memcpy(cflow, f, sizeof(flow));
    cflow->next_flow = 0;
    flows[hval] = cflow;
    return cflow;
  }
  else {
    // add flow to the beginning of the chain
    flow *old_flow = (flow *) xmalloc(sizeof(flow));
    memcpy(old_flow, cflow, sizeof(flow));
    memcpy(cflow, f, sizeof(flow));
    cflow->next_flow = old_flow;
  }
  return cflow;
}

static flow *
has_seen_flow(flow *f)
{
  int hval = hash_flow(f);
  flow *cflow = flows[hval];

  while (cflow) {
    if (flow_compare(cflow, f))
      return cflow;
    cflow = cflow->next_flow;
  }

  return 0;
}

static flow *
reverse_flow(flow *f)
{
  uint32_t tmp_ip;
  uint16_t tmp_port;

  tmp_ip = f->src_ip;
  f->src_ip = f->dst_ip;
  f->dst_ip = tmp_ip;

  tmp_port = f->sport;
  f->sport = f->dport;
  f->dport = tmp_port;
  return f;
}

static void
write_http_packet(flow *f)
{
  pentry_header ph;
  ph.length = htonl(f->msg_len_so_far);
  ph.port = htons(80);

  if (f->dir == CONN_DATA_REQUEST) {
    ph.ptype = htons(TYPE_HTTP_REQUEST);
    if (is_valid_http_request(f))
      write_msg_chains(f, client_file, &ph);
  }
  else {
    ph.ptype = htons(TYPE_HTTP_RESPONSE);
    write_msg_chains(f, server_file, &ph);
  }
}

static void
write_packet(flow *f)
{
  uint16_t tport;
  if (f->dir == CONN_DATA_REQUEST)
    tport = f->dport;
  else
    tport = f->sport;

  switch(tport) {
  case PORT_HTTP:
    write_http_packet(f);
  }
}

static void
my_callback(uint8_t * /*unused*/,
            const struct pcap_pkthdr *pkthdr,
            const uint8_t *packet)
{

  struct ether_header *eth = (struct ether_header*) (packet) ;
  int rval;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {

    struct ip *iph = (struct ip*) (packet + sizeof(struct ether_header));
    struct tcphdr *tcph = (struct tcphdr*)
        ((uint8_t*)iph + sizeof(struct ip));

    int len = htons(iph->ip_len) - 4*tcph->th_off - sizeof(struct ip);
    uint8_t *payload = (uint8_t*) tcph + 4*tcph->th_off;
    flow f;
    flow *cflow;
    flow *rflow;

    memset(&f, 0, sizeof(flow));
    f.src_ip = iph->ip_src.s_addr;
    f.dst_ip = iph->ip_dst.s_addr;
    f.sport  = ntohs(tcph->th_sport);
    f.dport  = ntohs(tcph->th_dport);
    f.flags  = tcph->th_flags;
    f.proto  = iph->ip_p;
    f.change_time = pkthdr->ts;

    if (tcph->th_flags & TH_SYN && !(tcph->th_flags & TH_ACK)) {
      f.dir = CONN_DATA_REQUEST;
      add_to_flows(&f);
      return;
    }

    else if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {
        f.dir = CONN_DATA_REPLY;
        add_to_flows(&f);
        return;
    }

    cflow = has_seen_flow(&f);
    if (!cflow)
      return;

    rflow = has_seen_flow(reverse_flow(&f));
    if (!rflow)
      return;

    rflow->ack_so_far = ntohl(tcph->th_ack);
    cflow->flags = cflow->flags | tcph->th_flags;

    if (len > 0 && ntohl(tcph->th_seq) >= cflow->ack_so_far) {
      if (rflow->msg_len_so_far > 0) {
        write_packet(rflow);
        free_msg_chain(rflow);
      }

      rval = add_msg_to_flow(cflow, payload, ntohl(tcph->th_seq), len);

      if (rval <= 0 && rval !=MSG_DUPLICATE && rval != CHAIN_TOO_LONG) {
        fprintf(stderr, "adding msg to flow failed %d %d\n", rval, len);
      }
    }


    if (cflow->flags & TH_RST || cflow->flags & TH_FIN) {
      if (rflow->msg_len_so_far > 0) {
        write_packet(rflow);
        free_msg_chain(rflow);
      }
      return;
    }
  }
}

static void
handle_pcap_file(const char *filename)
{
  descr = pcap_open_offline(filename, errbuf);
  if (!descr) {
    fprintf(stderr, "%s: %s\n", filename, errbuf);
    exit(1);
  }

  if (pcap_compile(descr, &fp, bp_filter, 1, netp) == -1) {
    fprintf(stderr, "Error calling pcap_compile on \"%s\"\n", bp_filter);
    exit(1);
  }

  /* set the compiled program as the filter */
  if (pcap_setfilter(descr, &fp) == -1) {
    fprintf(stderr,"Error setting filter\n");
    exit(1);
  }

  /* main pcap loop */
  pcap_loop(descr, -1, my_callback, 0);
  pcap_close(descr);
}

static void
list_files(const char *dirname)
{
  DIR *dip;
  struct dirent *dit;
  char *fname;
  size_t plen = strlen(dirname);

  if ((dip = opendir(dirname)) == 0) {
    perror("opendir");
    return;
  }

  while ((dit = readdir(dip)) != 0) {
    if (!strcmp(dit->d_name, ".") || !strcmp(dit->d_name, ".."))
      continue;

    size_t dlen = strlen(dit->d_name);
    fname = (char *)xmalloc(plen + dlen + 2);
    memcpy(fname, dirname, plen);
    fname[plen] = '/';
    memcpy(fname + plen + 1, dit->d_name, dlen);
    fname[plen + dlen + 1] = '\0';
    fprintf(stderr, "%s\n", fname);
    handle_pcap_file(fname);
    free(fname);
  }

  closedir(dip);
}

int
main(int argc, char **argv)
{
  int c;
  const char *dumpfile = 0;

  argv0 = argv[0];

  while ((c = getopt (argc, argv, "r:d:")) != -1) {
    switch (c) {
    case 'r':
      dumpfile = optarg;
      break;
    case 'd':
      dir_flag = 1;
      dumpfile = optarg;
      break;
    default:
      usage();
    }
  }

  if (!argv[optind] || !dumpfile)
    usage();

  bp_filter = xstrdup(argv[optind]);

  client_file = fopen("traces/client.out", "w");
  if (!client_file) {
    perror("traces/client.out");
    return 1;
  }
  server_file = fopen("traces/server.out", "w");
  if (!server_file) {
    perror("traces/server.out");
    return 1;
  }

  /* catch ^C print stats and exit */
  signal(SIGTERM, terminate);
  signal(SIGINT, terminate);
  signal(SIGHUP, terminate);

  if (dir_flag)
    list_files(dumpfile);
  else
    handle_pcap_file(dumpfile);

  return 0;
}
