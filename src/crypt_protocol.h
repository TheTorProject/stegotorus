/* Copyright 2011 Nick Mathewson

   You may do anything with this work that copyright law would normally
   restrict, so long as you retain the above notice(s) and this license
   in all redistributed copies and derived works.  There is no warranty.
*/

#ifndef CRYPT_PROTOCOL_H
#define CRYPT_PROTOCOL_H

typedef struct protocol_state_t protocol_state_t;
struct evbuffer;

protocol_state_t *protocol_state_new(int initiator);
void protocol_state_free(protocol_state_t *state);
int proto_send_initial_mesage(protocol_state_t *state, struct evbuffer *buf);
int proto_send(protocol_state_t *state,
               struct evbuffer *source, struct evbuffer *dest);
int proto_recv(protocol_state_t *state, struct evbuffer *source,
               struct evbuffer *dest);



#endif
