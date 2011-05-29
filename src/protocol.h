#include <event2/buffer.h>

#ifndef PROTOCOL_H
#define PROTOCOL_H

struct evbuffer;
struct listener_t;

#define DUMMY_PROTOCOL      1
#define OBFS2_PROTOCOL      2

/**
  This struct defines parameters of the protocol per-listener basis.
  
  By 'per-listener basis' I mean that the parameters defined here will
  be inherited by *all* connections opened from the listener_t that
  owns this protocol_params_t.
*/
typedef struct protocol_params_t {
  int is_initiator;
  struct sockaddr_storage target_address;
  int target_address_len;
  struct sockaddr on_address;
  int on_address_len;
  int mode;
  int proto; /* Protocol that this listener can speak. */
  char *shared_secret;
  size_t shared_secret_len;
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
int proto_recv(struct protocol_t *proto, void *source, void *dest);


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
  int (*recv)(void *state, 
              struct evbuffer *source,
              struct evbuffer *dest);

} protocol_vtable;

#endif
