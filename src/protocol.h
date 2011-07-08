/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

struct evbuffer;
struct listener_t;
struct sockaddr;

#define DUMMY_PROTOCOL      1
#define OBFS2_PROTOCOL      2

/**
  This struct defines parameters of the protocol per-listener basis.

  By 'per-listener basis' I mean that the parameters defined here will
  be inherited by *all* connections opened from the listener_t that
  owns this protocol_params_t.
*/
typedef struct protocol_params_t {
  struct sockaddr *target_address;
  struct sockaddr *listen_address;
  char *shared_secret;
  size_t shared_secret_len;
  size_t target_address_len;
  size_t listen_address_len;
  int is_initiator;
  int mode;
  int proto; /* Protocol that this listener can speak. */
} protocol_params_t;

struct protocol_t {
  /* protocol vtable */
  struct protocol_vtable *vtable;

  /* This protocol specific struct defines the state of the protocol
     per-connection basis.

     By 'protocol specific' I mean that every protocol has it's own
     state struct. (for example, obfs2 has obfs2_state_t)

     By 'per-connection basis' I mean that the every connection has a
     different protocol_t struct, and that's precisely the reason that
     this struct is owned by the conn_t struct.
  */
  void *state;
};
int set_up_protocol(int n_options, char **options,
                    struct protocol_params_t *params);
struct protocol_t *proto_new(struct protocol_params_t *params);
void proto_destroy(struct protocol_t *proto);
int proto_handshake(struct protocol_t *proto, void *buf);
int proto_send(struct protocol_t *proto, void *source, void *dest);
enum recv_ret proto_recv(struct protocol_t *proto, void *source, void *dest);

void proto_params_free(protocol_params_t *params);

typedef struct protocol_vtable {
  /* Initialization function: Fills in the protocol vtable. */
  int (*init)(int n_options, char **options,
              struct protocol_params_t *params);

  /* Destructor: Destroys the protocol state.  */
  void (*destroy)(void *state);

  /* Constructor: Creates a protocol object. */
  void *(*create)(struct protocol_t *proto_params,
                  struct protocol_params_t *parameters);

  /* does handshake. Not all protocols have a handshake. */
  int (*handshake)(void *state,
                   struct evbuffer *buf);

  /* send data function */
  int (*send)(void *state,
              struct evbuffer *source,
              struct evbuffer *dest);

  /* receive data function */
  enum recv_ret (*recv)(void *state,
                        struct evbuffer *source,
                        struct evbuffer *dest);

} protocol_vtable;

#endif
