#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>
#include <stdlib.h>

#include "network.h"

#define SOCKS5_VERSION        5
#define SOCKS5_ATYP_IPV4      1
#define SOCKS5_ATYP_FQDN      3
#define SOCKS5_CMD_CONNECT    1
#define SOCKS5_METHOD_NOAUTH  0 /* noauth is our auth; for now. */

/* XXX Minimum SOCKS _client_ packet is 3 bytes (Version Query)... maybe*/
#define MIN_SOCKS_PACKET 3


/**
   Client ------------------------> Server
          Method Negotiation Packet
          
   Client <------------------------ Server
          Method Negotiation Reply
          
   Client ------------------------> Server
               Client request 
               
   Client <------------------------ Server
               Server reply
               
   "Method Negotiation Packet" is handled by: socks5_handle_auth()
   "Method Negotiation Reply" is done by: socks5_reply_auth()
   "Client request" is handled by: socks5_handle_request()
   "Server reply" is handled by: socks5_reply_request() 
   
   XXX: I call the first "Method Negotiation *" packets "auth"
   through the code. This should change.
*/
   
/* SOCKS Request (Client -> Server) */
typedef struct socks5_req {
  uchar    version;     /* Version number */
  uchar    cmd;         /* Command */
  uchar    rsv;         /* Reserved */
  uchar    atyp;        /* Address type */
  uint32_t destaddr;    /* Dest address */
  uint16_t destport;    /* Dest port */
} socks5_req; 

/* SOCKS Reply (Server -> Client) */
struct socks5_repl {
  uchar version;
  uchar rep;  /* Reply field */
  uchar rsv;
  uchar atyp;
  uint32_t bndaddr;
  uint16_t bndport;
}

/**
   This function handles connection requests by authenticated SOCKS
   clients.
   
   Connection Request (Client -> Server):
   struct socks5_req, for reference.
*/

socks5_handle_request(struct evbuffer *source) {
  /* XXX 9 is not right here. */
  if (evbuffer_get_length(source) < 9) {
    printf("socks: request packet is too small.\n");
    return -1;
  }
    
  /* check error codes */
  socks5_req req = malloc(sizeof(socks5_req));
  evbuffer_remove(source, req, 9);
  
  struct sockaddr_in rep_in;
  memset(&rep_in, 0, sizeof(rep_in));
  
  /* We do no checkign in destaddr and destport.
     We also only support CONNNECT for now.
     Let's see how this goes. */
  if (req.cmd != SOCKS5_CMD_CONNECT || req.reserved != 0x00) {
    printf("socks: Only CONNECT supported. Sowwy!\n"); 
    return -1;
  }
  
  switch(req.atyp) {
  case SOCKS5_ATYP_IPV4:
    rep_in.sin_family = AF_INET;
    rep_in.sin_addr.s_addr = req.destaddr;
    break;
  default:  /* Do we actually need FQDN support? */
    return -1;
  }
  
  rep_in.sin_port = req.destport;
  
  /* Since for now we only support CONNECT. Let's CONNECT. */
  return socks5_connect(&rep_in, req, conn);
}
  
/*
  In this function we connect to the specified host and
  reply to our client. 
  
  Server Reply (Server -> Client):
  struct socks5_repl, for reference. 
*/
int
socks5_connect(void, conn_t *conn) {
}
  
/**
   This function handles the initial SOCKS packet sent by
   client, which negotiates the version and method of SOCKS.
   If the packet is actually valid, we reply.
   
   Method Negotiation Packet (Client -> Server):
   | version | nmethods | methods[nmethods] | 
       1b          1b           1-255b     
*/
int
socks5_handle_auth(struct evbuffer *source, conn_t *conn) {
  unsigned int found_noauth, i;
  
  /* We have checked that the length is more than 3,
     so we should be safe now. Just sayin'. */
  evbuffer_remove(source, nmethods, 1);
  
  /* XXX Careful with this check. */
  if (evbuffer_get_length(source) < nmethods) {
    printf("socks: nmethods is lying!\n");
    return -1;
  }
  
  /* check error codes */
  uchar *p;
  p = malloc(nmethods);
  evbuffer_remove(source, p, nmethods);
  
  for (found_noauth=0, i=0; i<nmethods ; i++) {
    if (p[i] == SOCKS5_METHOD_NOAUTH) {
      found_noauth = 1;
      break;
    }
  }
  
  if (!found_noauth) {
    printf("socks: methods SOCKS5_METHOD_NOAUTH not found!\n");
    return -1;
  }
  
  /* SOCKS auth/negotiation is done! */
  conn->done_socks_auth = 1;
  
  /* Since we made it 'till here, we should also reply! */
  if (socks5_reply_auth(conn))
    return 1;
  else
    return -1;
}
    
/**
   This function replies to a method negotiation packet,
   it's called by socks5_handle_auth().
   
   Method Negotiation Reply (Server -> Client):
   | version | method selected |
       1b           1b
*/
int
socks5_reply_auth(conn_t *conn)
{
  uchar reply[2];
  reply[0] = SOCKS5_VERSION;
  reply[1] = SOCKS5_METHOD_NOAUTH;
  
  /* XXX This just won't work. */
  evbuffer_add(bufferevent_get_output(output), reply, 2);
}

/**
   "STARTING POINT"
   We are given data from the network. 
   Figure out if it's SOCKS data, if it is:
   * if the connection hasn't passed the version negotiation,
     do it now.
   * if we know the connection, handle it's queries.
*/
/* evbuffer should become bufferevent!!! */
/* we are having too much fun with evbuffer_remove(),
    maybe we should dump everything in a normal buffer and
    use that. */
static void
read_data_from_network(struct evbuffer *source, void *arg)
{
  conn_t *conn = arg;
  /* First byte of SOCKS data is always version.
     If it isn't version; it isn't SOCKS! */
  uchar version;
  if (evbuffer_get_length(source) < MIN_SOCKS_PACKET) {
    printf("socks: The packet is too small.\n");
    return -1;
  }
  
  evbuffer_remove(source, version, 1);
  
  switch(version) {
  case SOCKS5_VERSION:
    if (!conn->done_socks_auth) { /* We don't know this connection. */
      if (socks5_handle_auth(source,conn) < 0) /* Let's authenticate. */
        return -1;
    }
    else { /* We know this connection. */
      socks5_handle_request(source); /* Let's see what it wants */
    }
    break;
  default: /* Yes, rejecting even SOCKS4. We are that badass */
    printf("socks: Nice packet! Now beat it!\n");
    break;
  }  
}

