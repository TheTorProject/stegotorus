#ifndef PROTOCOL_H
#define PROTOCOL_H

/* ASN I'm gonna be calling crypt_protocol.c BRL_RPOTOCOL for now. Yes. */
#define DUMMY_PROTOCOL    0
#define OBFS2_PROTOCOL      1


struct protocol_t *set_up_protocol(int protocol);
void *proto_init(struct protocol_t *proto, void *arg);
void proto_destroy(struct protocol_t *proto);
int proto_handshake(struct protocol_t *proto, void *buf);
int proto_send(struct protocol_t *proto, void *source, void *dest);
int proto_recv(struct protocol_t *proto, void *source, void *dest);



/* ASN Why the hell do half of them return int? FIXME */
struct protocol_t {
  /* Constructor: creates the protocol; sets up functions etc. */
  int (*new)(struct protocol_t *self);
  /* Destructor */
  void (*destroy)(void *state);

  /* does nessesary initiation steps; like build a proto state etc. */
  void *(*init)(void *arg);

  /* does handshake. Supposedly all protocols have a handshake. */
  int (*handshake)(void *state, void *buf);

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
