#ifndef PROTOCOL_H
#define PROTOCOL_H

#define DUMMY_PROTOCOL      0
#define OBFS2_PROTOCOL      1

struct evbuffer;

int set_up_protocol(int protocol);
struct protocol_t *proto_new(int protocol, int arg);
void proto_destroy(struct protocol_t *proto);
int proto_handshake(struct protocol_t *proto, void *buf);
int proto_send(struct protocol_t *proto, void *source, void *dest);
int proto_recv(struct protocol_t *proto, void *source, void *dest);


typedef struct protocol_vtable {
  /* Constructor: creates the protocol; sets up functions etc. */
  int (*init)(struct protocol_t *self);
  /* Destructor */
  void (*destroy)(void *state);

  /* does nessesary initiation steps; like build a proto state etc. */
  void *(*create)(struct protocol_t *proto_struct,
                  int is_initiator);

  /* does handshake. Supposedly all protocols have a handshake. */
  int (*handshake)(void *state,
                   struct evbuffer *buf);

  /* send data function */
  int (*send)(void *state, 
              struct evbuffer *source,
              struct evbuffer *dest);

  /* receive data function */
  int (*recv)(void *state, 
              struct evbuffer *source,
              struct evbuffer *dest);
} protocol_vtable;

struct protocol_t {
  /* protocol */
  int proto;

  /* protocol vtable */
  protocol_vtable *vtable;

  /* ASN do we need a proto_get_state()? */
  void *state;
};

#endif
