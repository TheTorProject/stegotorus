#ifndef PROTOCOL_H
#define PROTOCOL_H

/* ASN I'm gonna be calling crypt_protocol.c BRL_RPOTOCOL for now. Yes. */
#define BRL_PROTOCOL      1

struct protocol_t *set_up_protocol(int protocol);

/* ASN */
struct protocol_t {
  /* Constructor: creates the protocol; sets up functions etc. */
  void *(*new)(struct protocol_t *self);
  /* Destructor */
  void (*destroy)(void *arg);

  /* does nessesary initiation steps; like build a proto state etc. */
  void *(*init)(void *arg);

  /* does handshake. Supposedly all protocols have a handshake. */
  void *(*handshake)(void *state, void *buf);
  /* send data function */
  int (*send)(void *state, void *source,
              void *dest);
  /* receive data function */
  int (*recv)(void *state, void *source,
              void *dest);

  /* ASN do we need a proto_get_state()? */
  void *state;
};

#endif
