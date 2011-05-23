#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SOCKS_PRIVATE
#include "socks.h"
#include "util.h"

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/bufferevent.h>


/**
   General SOCKS5 idea:

   Client ------------------------> Server
          Method Negotiation Packet

   Client <------------------------ Server
          Method Negotiation Reply

   Client ------------------------> Server
               Client request

   Client <------------------------ Server
               Server reply

   "Method Negotiation Packet" is handled by: socks5_handle_negotiation()
   "Method Negotiation Reply" is done by: socks5_do_negotiation()
   "Client request" is handled by: socks5_handle_request()
   "Server reply" is done by: socks5_send_reply
*/

static int socks5_do_negotiation(struct evbuffer *dest,
                                    unsigned int neg_was_success);

typedef unsigned char uchar;

socks_state_t *
socks_state_new(void)
{
  socks_state_t *state = calloc(1, sizeof(socks_state_t));
  if (!state)
    return NULL;
  state->state = ST_WAITING;

  return state;
}

void
socks_state_free(socks_state_t *s)
{
  memset(s,0x0b, sizeof(socks_state_t));
  free(s);
}
/**
   This function handles connection requests by authenticated SOCKS
   clients.
   Considering a request packet from 'source', it evaluates it and pushes
   the appropriate reply to 'dest'.
   If the request was correct and can be fulfilled, it connects 'output'
   to the location the client specified to actually set up the proxying.

   XXX: You will notice some "sizeof(req)-1" that initially make no
   sense, but because of handle_socks() removing the version byte,
   there are only 3 bytes (==sizeof(req)-1) between the start
   of 'source' and addrlen. I don't know if replacing it with plain "3"
   would make more sense.

   Client Request (Client -> Server)
*/
int
socks5_handle_request(struct evbuffer *source, struct parsereq *parsereq)
{
  /** XXX: max FQDN size is 255. */
  /* #define MAXFQDN */
  char destaddr[255+1]; /* Dest address */
  u_int16_t destport;    /* Dest port */

  unsigned int buflength = evbuffer_get_length(source);

  if (buflength < SIZEOF_SOCKS5_STATIC_REQ+1) {
    printf("socks: request packet is too small (1).\n");
    return 0;
  }

  /* We only need the socks5_req and an extra byte to get
     the addrlen in an FQDN request.
  */
  uchar p[SIZEOF_SOCKS5_STATIC_REQ+1];
  if (evbuffer_copyout(source, p, SIZEOF_SOCKS5_STATIC_REQ+1) < 0)
    goto err;

  /* p[0] = Version
     p[1] = Command field
     p[2] = Reserved field */
  if (p[0] != SOCKS5_VERSION || p[1] != SOCKS5_CMD_CONNECT || p[2] != 0x00) {
    printf("socks: Only CONNECT supported. Sowwy!\n");
    goto err;
  }

  unsigned int addrlen,af,extralen=0;
  /* p[3] is Address type field */
  switch(p[3]) {
  case SOCKS5_ATYP_IPV4:
    addrlen = 4;
    af = AF_INET;
    /* minimum packet size:
       socks5_req - <version byte> + addrlen + port */
    break;
  case SOCKS5_ATYP_IPV6:
    addrlen = 16;
    af = AF_INET6;
    break;
  case SOCKS5_ATYP_FQDN:  /* Do we actually need FQDN support? */
    addrlen = p[4];
    extralen = 1;
    af = AF_UNSPEC;
    /* as above, but we also have the addrlen field byte */
    break;
  default:
    printf("socks: Address type not supported. Go away.\n");
    goto err;
  }

  int minsize = SIZEOF_SOCKS5_STATIC_REQ + addrlen + extralen + 2;
  if (buflength < minsize) {
    printf("socks: request packet too small %d:%d (2)\n", buflength, minsize);
    return 0;
  }

  /* Drain data from the buffer to get to the good part, the actual
     address and port. */
  if (evbuffer_drain(source, SIZEOF_SOCKS5_STATIC_REQ) == -1)
    goto err;
  /* If it is an FQDN request, drain the addrlen byte as well. */
  if (af == AF_UNSPEC)
    if (evbuffer_drain(source, 1) == -1)
      goto err;

  if (evbuffer_remove(source, destaddr, addrlen) != addrlen)
    assert(0);

  if (evbuffer_remove(source, (char *)&destport, 2) != 2)
    assert(0);

  destaddr[addrlen] = '\0';

  if (af == AF_UNSPEC) {
    assert(addrlen < sizeof(parsereq->addr));
    memcpy(parsereq->addr, destaddr, addrlen+1);
  } else {
    char a[16];
    assert(addrlen <= 16);
    memcpy(a, destaddr, addrlen);
    if (evutil_inet_ntop(af, destaddr, parsereq->addr, sizeof(parsereq->addr)) == NULL)
      goto err;
  }

  parsereq->port = ntohs(destport);
  parsereq->af = af;

  return 1;

 err:
  return -1;
}

/**
   This sends the appropriate reply to the client on 'reply_dest'.

   Server Reply (Server -> Client):
   | version | rep | rsv | atyp | destaddr           | destport
     1b         1b    1b    1b       4b/16b/1+Nb         2b
*/
int
socks5_send_reply(struct evbuffer *reply_dest, socks_state_t *state,
                  int status)
{
  /* This is the buffer that contains our reply to the client. */
  uchar p[4];
  uchar addr[16];
  const char *extra = NULL;
  int addrlen;
  uint16_t port;
  /* We either failed or succeded.
     Either way, we should send something back to the client */
  p[0] = SOCKS5_VERSION;    /* Version field */
  p[1] = (unsigned char) status; /* Reply field */
  p[2] = 0;                 /* Reserved */
  if (state->parsereq.af == AF_UNSPEC) {
    addrlen = 1;
    addr[0] = strlen(state->parsereq.addr);
    extra = state->parsereq.addr;
    p[3] = SOCKS5_ATYP_FQDN;
  } else {
    addrlen = (state->parsereq.af == AF_INET) ? 4 : 16;
    p[3] = (state->parsereq.af == AF_INET) ? SOCKS5_ATYP_IPV4 : SOCKS5_ATYP_IPV6;
    evutil_inet_pton(state->parsereq.af, state->parsereq.addr, addr);
  }
  port = htons(state->parsereq.port);

  evbuffer_add(reply_dest, p, 4);
  evbuffer_add(reply_dest, addr, addrlen);
  if (extra)
    evbuffer_add(reply_dest, extra, strlen(extra));
  evbuffer_add(reply_dest, &port, 2);

  state->state = ST_SENT_REPLY; /* SOCKS phase is now done. */

  return 1;
}

/**
   This function handles the initial SOCKS5 packet in 'source' sent by
   the client, which negotiates the version and method of SOCKS.  If
   the packet is actually valid, we reply to 'dest'.

   Method Negotiation Packet (Client -> Server):
   nmethods | methods[nmethods] |
       b           1-255b
*/
int
socks5_handle_negotiation(struct evbuffer *source,
                          struct evbuffer *dest, socks_state_t *state)
{
  unsigned int found_noauth, i;

  uchar nmethods;

  evbuffer_copyout(source, &nmethods, 1);

  if (evbuffer_get_length(source) < nmethods + 1) {
    return 0; /* need more data */
  }

  evbuffer_drain(source, 1);

  uchar *p;
  /* XXX user controlled malloc(). range should be: 0x00-0xff */
  p = malloc(nmethods);
  if (!p) {
    printf("malloc failed!\n");
    return -1;
  }
  if (evbuffer_remove(source, p, nmethods) < 0)
    assert(0);

  for (found_noauth=0, i=0; i<nmethods ; i++) {
    if (p[i] == SOCKS5_METHOD_NOAUTH) {
      found_noauth = 1;
      break;
    }
  }

  free(p);

  return socks5_do_negotiation(dest,found_noauth);
}

/**
   This function sends a method negotiation reply to 'dest'.
   If 'neg_was_success' is true send a positive response,
   otherwise send a negative one.
   It returns -1 if no suitable negotiation methods were found,
   or if there was an error during replying.

   Method Negotiation Reply (Server -> Client):
   | version | method selected |
       1b           1b
*/
static int
socks5_do_negotiation(struct evbuffer *dest, unsigned int neg_was_success)
{
  uchar reply[2];
  reply[0] = SOCKS5_VERSION;

  reply[1] = neg_was_success ? SOCKS5_METHOD_NOAUTH : SOCKS5_METHOD_FAIL;

  if (evbuffer_add(dest, reply, 2) == -1 || !neg_was_success)
    return -1;
  else
    return 1;
}

/* rename to socks4_handle_request or something. */
int
socks4_read_request(struct evbuffer *source, socks_state_t *state)
{
  /* Format is:
       1 byte: Socks version (==4, already read)
       1 byte: command code [== 1 for connect]
       2 bytes: port
       4 bytes: IPv4 address
       X bytes: userID, terminated with NUL
       Optional: X bytes: domain, terminated with NUL */
  uchar header[7];
  int is_v4a;
  uint16_t portnum;
  uint32_t ipaddr;
  struct evbuffer_ptr end_of_user, end_of_hostname;
  size_t user_len, hostname_len=0;
  if (evbuffer_get_length(source) < 7)
    return 0; /* more bytes needed */
  evbuffer_copyout(source, (char*)header, 7);
  if (header[0] != 1) {
    printf("socks: Only CONNECT supported.\n");
    return -1;
  }
  memcpy(&portnum, header+1, 2);
  memcpy(&ipaddr, header+3, 4);
  portnum = ntohs(portnum);
  ipaddr = ntohl(ipaddr);
  is_v4a = (ipaddr & 0xff) != 0 && (ipaddr & 0xffffff00)==0;

  evbuffer_ptr_set(source, &end_of_user, 7, EVBUFFER_PTR_SET);
  end_of_user = evbuffer_search(source, "\0", 1, &end_of_user);
  if (end_of_user.pos == -1) {
    if (evbuffer_get_length(source) > SOCKS4_MAX_LENGTH)
      return -1;
    return 0;
  }
  user_len = end_of_user.pos - 7;
  if (is_v4a) {
    if (end_of_user.pos == evbuffer_get_length(source)-1)
      return 0; /*more data needed */
    end_of_hostname = end_of_user;
    evbuffer_ptr_set(source, &end_of_hostname, 1, EVBUFFER_PTR_ADD);
    end_of_hostname = evbuffer_search(source, "\0", 1, &end_of_hostname);
    if (end_of_hostname.pos == -1) {
      if (evbuffer_get_length(source) > SOCKS4_MAX_LENGTH)
        return -1;
      return 0;
    }
    hostname_len = end_of_hostname.pos - end_of_user.pos - 1;
    if (hostname_len >= sizeof(state->parsereq.addr)) {
      printf("socks4a: Hostname too long\n");
      return -1;
    }
  }

  /* Okay.  If we get here, all the data is available. */
  evbuffer_drain(source, 7+user_len+1); /* discard username */
  state->parsereq.af = AF_INET; /* SOCKS4a is IPv4 only */
  state->parsereq.port = portnum;
  if (is_v4a) {
    evbuffer_remove(source, state->parsereq.addr, hostname_len);
    state->parsereq.addr[hostname_len] = '\0';
    evbuffer_drain(source, 1);
  } else {
    struct in_addr in;
    in.s_addr = htonl(ipaddr);
    if (evutil_inet_ntop(AF_INET, &in, state->parsereq.addr, sizeof(state->parsereq.addr)) == NULL)
      return -1;
  }

  return 1;
}

int
socks4_send_reply(struct evbuffer *dest, socks_state_t *state, int status)
{
  uint16_t portnum;
  struct in_addr in;
  uchar msg[8];
  portnum = htons(state->parsereq.port);
  if (evutil_inet_pton(AF_INET, state->parsereq.addr, &in)!=1)
    in.s_addr = 0;

  /* Nul byte */
  msg[0] = 0;
  /* convert to socks4 status */
  msg[1] = (status == SOCKS5_REP_SUCCESS) ? SOCKS4_SUCCESS : SOCKS4_FAILED;
  memcpy(msg+2, &portnum, 2);
  /* ASN: What should we do here in the case of an FQDN request? */
  memcpy(msg+4, &in.s_addr, 4);
  evbuffer_add(dest, msg, 8);

  return 1;
}

/**
   We are given data from the network.
   If we haven't negotiated with the connection, we try to negotiate.
   If we have already negotiated, we suppose it's a CONNECT request and
   try to be helpful.

   Returns 1 on done, -1 on unrecoverable error, 0 on "need more bytes
*/
int
handle_socks(struct evbuffer *source, struct evbuffer *dest,
             socks_state_t *socks_state)
{
  int r;
  if (socks_state->broken)
    return -1;

  if (evbuffer_get_length(source) < MIN_SOCKS_PACKET) {
    printf("socks: Packet is too small.\n");
    return 0;
  }

  /* ST_SENT_REPLY connections shouldn't be here! */
  assert(socks_state->state != ST_SENT_REPLY &&
         socks_state->state != ST_HAVE_ADDR);

  if (socks_state->version == 0) {
    /* First byte of all SOCKS data is the version field. */
    evbuffer_remove(source, &socks_state->version, 1);
    if (socks_state->version != SOCKS5_VERSION &&
        socks_state->version != SOCKS4_VERSION) {
      printf("socks: unexpected version %d", (int)socks_state->version);
      goto broken;
    }
    dbg(("Got version %d\n",(int)socks_state->version));
  }

  switch(socks_state->version) {
  case SOCKS4_VERSION:
    if (socks_state->state == ST_WAITING) {
      r = socks4_read_request(source, socks_state);
      if (r == -1)
        goto broken;
      else if (r == 0)
        return 0;
      socks_state->state = ST_HAVE_ADDR;
      return 1;
    }
    break;
  case SOCKS5_VERSION:
    if (socks_state->state == ST_WAITING) {
      /* We don't know this connection. We have to do method negotiation. */
      r = socks5_handle_negotiation(source,dest,socks_state);
      if (r == -1)
        goto broken;
      else if (r == 0)
        return 0;
      else if (r == 1)
        socks_state->state = ST_NEGOTIATION_DONE;
    }
    if (socks_state->state == ST_NEGOTIATION_DONE) {
      /* We know this connection. Let's see what it wants. */
      r = socks5_handle_request(source,&socks_state->parsereq);
      if (r == -1)
        goto broken;
      else if (r == 1)
        socks_state->state = ST_HAVE_ADDR;
      return r;
    }
    break;
  default:
    goto broken;
  }

  return 0;
 broken:
  socks_state->broken = 1;
  return -1;
}

enum socks_status_t
socks_state_get_status(const socks_state_t *state)
{
  return state->state;
}

int
socks_state_get_address(const socks_state_t *state,
                        int *af_out,
                        const char **addr_out,
                        int *port_out)
{
  if (state->state != ST_HAVE_ADDR && state->state != ST_SENT_REPLY)
    return -1;
  *af_out = state->parsereq.af;
  *addr_out = (char*) state->parsereq.addr;
  *port_out = state->parsereq.port;
  return 0;
}

int
socks_state_set_address(socks_state_t *state, const struct sockaddr *sa)
{
  int port;
  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
    port = sin->sin_port;
    if (evutil_inet_ntop(AF_INET, &sin->sin_addr, state->parsereq.addr, sizeof(state->parsereq.addr)) == NULL)
      return -1;
  } else if (sa->sa_family == AF_INET6) {
    if (state->version == 4) {
      printf("Oops; socks4 doesn't allow ipv6 addresses\n");
      return -1;
    }
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
    port = sin6->sin6_port;
    if (evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, state->parsereq.addr, sizeof(state->parsereq.addr)) == NULL)
      return -1;
  } else {
    printf("Unknown address family %d\n", sa->sa_family);
    return -1;
  }

  state->parsereq.port = ntohs(port);
  state->parsereq.af = sa->sa_family;
  return 0;
}

int
socks_send_reply(socks_state_t *state, struct evbuffer *dest, int status)
{
  if (state->version == 5)
    return socks5_send_reply(dest, state, status);
  else if (state->version == 4)
    return socks4_send_reply(dest, state, status);
  else
    return -1;
}

