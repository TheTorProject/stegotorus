#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SOCKS_PRIVATE
#include "socks.h"
#include "crypt.h"

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/bufferevent.h>


/**
   General idea:
   
   Client ------------------------> Server
          Method Negotiation Packet
          
   Client <------------------------ Server
          Method Negotiation Reply
          
   Client ------------------------> Server
               Client request 
               
   Client <------------------------ Server
               Server reply
               
   "Method Negotiation Packet" is handled by: socks5_handle_negotiation()
   "Method Negotiation Reply" is done by: socks5_do_auth()
   "Client request" is handled by: socks5_validate_request()
   
   XXX: Do we actually need FQDN support? 
   It's a lot of implementation trouble for nothing, since our bridges
   are referenced with IPV4 addresses. Anyway, I implemented it.
*/

static int socks5_do_auth(struct evbuffer *dest);
static int socks5_send_reply(struct evbuffer *reply_dest, socks_state_t *state,
                             int status);


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
  
  /* buflength is without the version byte. */
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
  
  /* OpenSSH does this check here. I don't know why.
     addrlen is uchar casted to uint, which means it
     can't be over 255. And in any case the overflow
     would have already happened. XXX */
#define NI_MAXHOST 1025
  if (af == AF_UNSPEC)
    if (addrlen >= NI_MAXHOST)
      goto err;

  if (af != AF_UNSPEC) {
    /* XXX the inet_ntop() arguments seems to work, but it feels
       a bit awkward */
    char a[16];
    assert(addrlen <= 16);
    memcpy(a, destaddr, addrlen);
    if (inet_ntop(af, a, destaddr, sizeof(destaddr)) == NULL)
      goto err;
  }
  
  /* XXX FIX! NI_MAXSERV: I don't even remember where I found this!! */
  snprintf(parsereq->port, NI_MAXSERV, "%u", (unsigned)ntohs(destport));
  strncpy(parsereq->addr, destaddr, 255+1);
  parsereq->addr[255]='\0';/*ensure nul-termination*/
  parsereq->af = af;
  
  return 1;
  
 err:
  return -1;
}  

/**
   This sends the appropriate reply to the client on 'reply_dest'.

   Server Reply (Server -> Client):
   | version | rep | rsv | atyp | destaddr | destport
   1b       1b    1b    1b       4b         2b
*/
static int
socks5_send_reply(struct evbuffer *reply_dest, socks_state_t *state,
                  int status)
{
  /* This is the buffer that contains our reply to the client. */
  uchar p[SIZEOF_SOCKS5_REQ_REPLY];
  
  /* We either failed or succeded.
     Either way, we should send something back to the client */
  p[0] = SOCKS5_VERSION;    /* Version field */
  p[1] = (unsigned char) status; /* Reply field */
  p[2] = 0;                 /* Reserved */
  p[3] = SOCKS5_ATYP_IPV4;  /* Address Type */
  /* Leaving destport/destaddr to zero */
  /* XXXX this is not correct */
  memset(&p[4], 0, 6); /* destport/destaddr */

  evbuffer_add(reply_dest,
               p, SIZEOF_SOCKS5_REQ_REPLY);

  state->state = ST_SENT_REPLY; /* SOCKS phase is now done. */

  if (status == SOCKS5_REP_SUCCESS) {
    return 1;
  } else {
    return -1;
  }
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
    goto err;
  }
  if (evbuffer_remove(source, p, nmethods) < 0)
    assert(0);
  
  for (found_noauth=0, i=0; i<nmethods ; i++) {
    if (p[i] == SOCKS5_METHOD_NOAUTH) {
      found_noauth = 1;
      break;
    }
  }
  
  if (!found_noauth) {
    printf("socks: Client doesn't seem to support NOUATH!\n");
    /* XXX should send back [05 FF] to say, I'm socks5 and I didn't like any
       of those methods */
    goto err;
  }
  
  /* Packet is legit. Rejoice! */
  free(p);

  return socks5_do_auth(dest);
  
 err: 
  assert(p);
  free(p);
  
  return -1;
}
    
/**
   This function sends a method negotiation reply to 'dest'.
   it's called by socks5_handle_negotiation().
   
   Method Negotiation Reply (Server -> Client):
   | version | method selected |
       1b           1b
*/
static int
socks5_do_auth(struct evbuffer *dest)
{
  uchar reply[2];
  reply[0] = SOCKS5_VERSION;
  reply[1] = SOCKS5_METHOD_NOAUTH;
  
  if (evbuffer_add(dest, reply, 2) == -1)
    return -1;
  else {
    return 1;
  }
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
  assert(socks_state->state != ST_SENT_REPLY);

  if (socks_state->version == 0) {
    /* First byte of all SOCKS data is the version field. */
    evbuffer_remove(source, &socks_state->version, 1);
    if (socks_state->version != SOCKS5_VERSION) {
      printf("socks: unexpected version %d", (int)socks_state->version);
      goto broken;
    }
  }

  switch(socks_state->version) {
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
      else
        return r;
    }
    break;
  default:
    printf("socks: Nice packet! Now beat it!\n");
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
                        const char **service_out)
{
  if (state->state != ST_HAVE_ADDR && state->state != ST_SENT_REPLY)
    return -1;
  *af_out = state->parsereq.af;
  *addr_out = (char*) state->parsereq.addr;
  *service_out = (char*) state->parsereq.port;
  return 0;
}

int
socks_send_reply(socks_state_t *state, struct evbuffer *dest, int status)
{
  if (state->version == 5)
    return socks5_send_reply(dest, state, status);
  else
    return -1;
}
