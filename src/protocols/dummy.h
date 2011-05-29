#ifndef DUMMY_H
#define DUMMY_H

struct protocol_t;
struct evbuffer;
struct protocol_params_t;

int dummy_init(void);
void *dummy_new(struct protocol_t *proto_struct, struct protocol_params_t *params);

#endif
