#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "network.h"
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
               
   "Method Negotiation Packet" is handled by: socks5_handle_auth()
   "Method Negotiation Reply" is done by: socks5_do_auth()
   "Client request" is handled by: socks5_handle_request()
   "Server reply" is handled by: socks5_do_connect(), since we only
   support CONNECT commands anyway.
   
   XXX: Do we actually need FQDN support? 
   It's a lot of implementation trouble for nothing, since our bridges
   are referenced with IPV4 addresses. Anyway, I implemented it.
*/

static int socks5_handle_auth(struct evbuffer *source, conn_t *conn);
static int socks5_handle_request(struct evbuffer *source, conn_t *conn);
static int socks5_do_auth(conn_t *conn);
static int socks5_do_connect(char* destaddr, char *port, conn_t *conn);

socks_state_t *
socks_state_new(void)
{
  socks_state_t *state = calloc(1, sizeof(socks_state_t));
  if (!state)
    return NULL;
  state->state = ST_WAITING;
  
  return state;
}
  

/**
   This function handles connection requests by authenticated SOCKS
   clients.
   
   XXX: You will notice some "sizeof(req)-1" that initially make no
   sense, but because of handle_socks() removing the version byte,
   there are only 3 bytes (==sizeof(req)-1) between the start
   of 'source' and addrlen. I don't know if replacing it with plain "3"
   would make more sense. 
   
   Client Request (Client -> Server)
*/
static int
socks5_handle_request(struct evbuffer *source, conn_t* conn) 
{
  /* SOCKS Request (Client -> Server) */
  struct socks5_req {
    uchar    version;     /* Version number */
    uchar    cmd;         /* Command */
    uchar    rsv;         /* Reserved */
    uchar    atyp;        /* Address type */
  } req; 
  /** max FQDN size is 255. */ 
  char destaddr[255+1]; /* Dest address */
  u_int16_t destport;    /* Dest port */
  
  /* buflength is without the version byte. */
  unsigned int buflength = evbuffer_get_length(source);
  
  /* Remember, version byte of request was already extracted */
  if (buflength < sizeof(req)) {
    printf("socks: request packet is too small (1).\n");
    return -1;
  }
  
  /** XXX: Maybe we should reject high values of buflength? */
  uchar *p = malloc(buflength); 
  if (!p)
    return -1;
    
  
  /* We only need the socks5_req and an extra byte to get
     the addrlen in an FQDN request. "Conveniently" this is
     sizeof(req) since we have already removed the version byte.*/
  if (evbuffer_copyout(source, p, sizeof(req)) < 0)
    goto err;
  memcpy(&req.cmd, p, sizeof(req));  
  
  if (req.cmd != SOCKS5_CMD_CONNECT || req.rsv != 0x00) {
    printf("socks: Only CONNECT supported. Sowwy!\n"); 
    goto err;
  }
  
  unsigned int addrlen,af,minsize;
  switch(req.atyp) {
  case SOCKS5_ATYP_IPV4:
    addrlen = 4;
    af = AF_INET;
    /* minimum packet size:
       socks5_req - <version byte> + addrlen + port */
    minsize = sizeof(req) - 1 + addrlen + 2;
    break;
  case SOCKS5_ATYP_FQDN:  /* Do we actually need FQDN support? */
    addrlen = p[sizeof(req)-1];
    af = -1;
    /* as above, but we also have the addrlen field byte */
    minsize++;
    break;
  default:
    printf("socks: Not supported. Go away.\n");
    goto err;
  }
  
  if (buflength < minsize) {
    printf("socks: request packet too small %d:%d (2)\n", buflength, minsize);
    goto err;
  }
  
  /* Drain data from the buffer to get to the good part, the actual
     address and port. */
  if (evbuffer_drain(source, sizeof(req)-1) == -1)
    goto err;
  /* If it is an FQDN request, drain the addrlen byte as well. */
  if (req.atyp == SOCKS5_ATYP_FQDN)
    if (evbuffer_drain(source, 1) == -1)
      goto err;
  
  evbuffer_remove(source, (char *)&destaddr, addrlen);
  evbuffer_remove(source, (char *)&destport, 2);
  destaddr[addrlen] = '\0';
  
  /* OpenSSH does this check here. I don't know why.
     addrlen is uchar casted to uint, which means it
     can't be over 255. And in any case the overflow
     would have already happened. XXX */
  #define NI_MAXHOST 1025
  if (req.atyp == SOCKS5_ATYP_FQDN)
    if (addrlen >= NI_MAXHOST)
      goto err;

  char ntop[INET_ADDRSTRLEN];      
  if (req.atyp == SOCKS5_ATYP_IPV4) { 
    /* XXX the inet_ntop() arguments seems to work, but it feels
       a bit awkward */
    if (inet_ntop(af, destaddr, destaddr, sizeof(ntop)) == NULL)
      goto err;
  }
  
  char strport[NI_MAXSERV];
  snprintf(strport, sizeof(strport), "%u", ntohs(destport));
  if (socks5_do_connect(destaddr, strport, conn) <0)
    goto err;
  
  free(p);
  return 1;
  
 err:
  assert(p);
  free(p);
  
  return -1;
}  

/**
   This function does the actual CONNECT to <'destaddr','destport'>
   based on the address type 'type' (FQDN or IPV4).
   It then sends a reply to the client on 'conn'.
   
   Server Reply (Server -> Client)   
*/
static int
socks5_do_connect(char* destaddr, char *port, conn_t *conn)
{
  /* SOCKS Reply (Client -> Server) */
  struct {
    uchar    version;     /* Version number */
    uchar    rep;         /* Reply field */
    uchar    rsv;         /* Reserved */
    uchar    atyp;        /* Address type */
    unsigned int destaddr; /* Dest address */    
    u_int16_t destport;       /* Dest port */
  } socks5_repl; 
  unsigned int status;
  int res;
  
  struct addrinfo hints;
  struct addrinfo *servinfo;
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  
  res = getaddrinfo(destaddr, port, &hints, &servinfo);
  if (res == 0) { /* Everything is going fine. Connect. */
    if (bufferevent_socket_connect(conn->output,
                                   servinfo->ai_addr,
                                   (int) servinfo->ai_addrlen)<0)
      status = SOCKS5_REP_FAIL; /* connect failed. */
    else { /* connect succeeded. */
      status = SOCKS5_REP_SUCCESS; 
      bufferevent_enable(conn->output, EV_READ|EV_WRITE);
    }
  } else { /* error in getaddrinfo() */
    status = SOCKS5_REP_FAIL;
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
  }

  /* We either failed or succeded.
     Either way, we should send something back to the client */
  socks5_repl.version = SOCKS5_VERSION;
  socks5_repl.rep = status;
  socks5_repl.rsv = 0;
  socks5_repl.atyp = SOCKS5_ATYP_IPV4;
  /* Leaving destport/destaddr to zero */
  memset(&socks5_repl.destport, 0, 6); 
  
  evbuffer_add(bufferevent_get_output(conn->input),
               &socks5_repl, sizeof(socks5_repl));
  
  if (status == SOCKS5_REP_SUCCESS) {
    conn->socks_state->state = ST_OPEN; /* SOCKS phase is done now. */
    return 1;
  }
  else
    return -1;
}
   
/**
   This function handles the initial SOCKS packet sent by
   client, which negotiates the version and method of SOCKS.
   If the packet is actually valid, we reply.
   
   Method Negotiation Packet (Client -> Server):
   | version | nmethods | methods[nmethods] | 
       1b          1b           1-255b     
*/
static int
socks5_handle_auth(struct evbuffer *source, conn_t *conn) {
  unsigned int found_noauth, i;
  
  uchar nmethods;
  
  evbuffer_remove(source, &nmethods, 1);
  
  if (evbuffer_get_length(source) < nmethods) {
    printf("socks: nmethods is lying!\n");
    return -1;
  }
  
  uchar *p;
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
    goto err;
  }
  
  /* Since we made it 'till here, we should also reply! */
  if (socks5_do_auth(conn) < 0)  /* SOCKS auth/negotiation failed! */
    goto err;
  
  conn->socks_state->state = ST_NEGOTIATION_DONE;
  free(p);
  return 1;
  
 err: 
  assert(p);
  free(p);
  
  return -1;
}
    
/**
   This function replies to a method negotiation packet,
   it's called by socks5_handle_auth().
   
   Method Negotiation Reply (Server -> Client):
   | version | method selected |
       1b           1b
*/
static int
socks5_do_auth(conn_t *conn)
{
  uchar reply[2];
  reply[0] = SOCKS5_VERSION;
  reply[1] = SOCKS5_METHOD_NOAUTH;
  
  if (evbuffer_add(bufferevent_get_output(conn->input), reply, 2) == -1)
    return -1;
  else
    return 1;
}

/**
   We are given data from the network. 
   If we haven't negotiated with the connection, we try to negotiate.
   If we have already negotiated, we suppose it's a CONNECT request and
   try to be helpful.
*/
int
handle_socks(struct evbuffer *input, struct evbuffer *output, void *arg)
{
  if (evbuffer_get_length(input) < MIN_SOCKS_PACKET) {
    printf("socks: Packet is too small.\n");
    return -1;
  }
  
  conn_t *conn = arg;
  uchar version;
  
  /* First byte of all SOCKS data is the version field. */
  evbuffer_remove(input, &version, 1);
  
  switch(version) {
  case SOCKS5_VERSION:
    if (conn->socks_state->state == ST_WAITING) /* We don't know this connection. */
      return socks5_handle_auth(input,conn); /* Let's authenticate. */
    else /* We know this connection. */
      return socks5_handle_request(input, conn); /* Let's see what it wants */
    break;
  default: /* Yep, rejecting SOCKS4. We are that badass */
    printf("socks: Nice packet! Now beat it!\n");
    return -1;
  }  
  
  return 1;
}

