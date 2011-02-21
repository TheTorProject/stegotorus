#ifndef SOCKS_H
#define SOCKS_H

#include <netdb.h>

typedef struct socks_state_t socks_state_t;
struct evbuffer;

enum socks_status_t {
  /* Waiting for initial socks4 or socks5 message */
  ST_WAITING,
  /* Sent socks5 method negotiation message; waiting for request */
  ST_NEGOTIATION_DONE,
  /* Have received target address */
  ST_HAVE_ADDR,
  /* Have sent reply */
  ST_SENT_REPLY
};
int handle_socks(struct evbuffer *source,
                 struct evbuffer *dest, socks_state_t *socks_state);
socks_state_t *socks_state_new(void);
void socks_state_free(socks_state_t *s);

enum socks_status_t socks_state_get_status(const socks_state_t *state);
int socks_state_get_address(const socks_state_t *state,
                            int *af_out,
                            const char **addr_out,
                            int *port_out);
int socks_send_reply(socks_state_t *state, struct evbuffer *dest, int status);

#define SOCKS5_REP_SUCCESS     0x0
/* XXX there are more response codes than this! */
#define SOCKS5_REP_FAIL        0x01


#ifdef SOCKS_PRIVATE
#define SOCKS5_VERSION         0x05

#define SOCKS5_METHOD_NOAUTH   0x00

#define SOCKS5_CMD_CONNECT     0x01

#define SOCKS5_ATYP_IPV4       0x01
#define SOCKS5_ATYP_FQDN       0x03
#define SOCKS5_ATYP_IPV6       0x04

/* Minimum SOCKS packet length is 3 bytes:
   Method Negotiation Packet with 1 method */
#define MIN_SOCKS_PACKET       3

/* Size of a SOCKS request reply packet.
   Yes, it's static. Yes, it's 10. */
#define SIZEOF_SOCKS5_REQ_REPLY   10

/* Size of the static part of a SOCKS request:
   | version | cmd | rsv | atyp |
       1b       1b   1b     1b
*/
#define SIZEOF_SOCKS5_STATIC_REQ 4

struct parsereq {
  int af; /* Address family */
  char addr[255+1]; /* Address as string */
  int port;
};
struct socks_state_t {
  enum socks_status_t state;
  unsigned char version;
  unsigned char broken;
  struct parsereq parsereq;
};

int socks5_handle_negotiation(struct evbuffer *source,
                              struct evbuffer *dest, socks_state_t *state);
int socks5_handle_request(struct evbuffer *source,
                          struct parsereq *parsereq);
#endif

#endif
