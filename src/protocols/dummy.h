#ifndef DUMMY_H
#define DUMMY_H

struct protocol_t;
struct evbuffer;

int dummy_init(void);
void *dummy_new(struct protocol_t *proto_struct, int whatever, const char* whatever2);

#endif
