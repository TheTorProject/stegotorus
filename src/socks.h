#ifndef SOCKS_H
#define SOCKS_H

typedef struct socks_state_t socks_state_t;
struct evbuffer;

int handle_socks(struct evbuffer *input, 
                 struct evbuffer *output, void *arg);
socks_state_t *socks_state_new(void);

#define SOCKS5_VERSION         0x05

#define SOCKS5_METHOD_NOAUTH   0x00

#define SOCKS5_CMD_CONNECT     0x01

#define SOCKS5_ATYP_IPV4       0x01
#define SOCKS5_ATYP_FQDN       0x03

#define SOCKS5_REP_SUCCESS     0x0
#define SOCKS5_REP_FAIL        0x01

/* Minimum SOCKS packet length is 3 bytes:
   Method Negotiation Packet with 1 method */ 
#define MIN_SOCKS_PACKET       0x03

struct socks_state_t {
  enum {
    ST_WAITING,
    ST_NEGOTIATION_DONE,
    ST_OPEN,
  } state;
};

#endif
