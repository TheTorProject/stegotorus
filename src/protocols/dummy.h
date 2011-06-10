/* Copyright 2011 Nick Mathewson, George Kadianakis
   See LICENSE for other credits and copying information
*/
#ifndef DUMMY_H
#define DUMMY_H

struct protocol_t;
struct evbuffer;
struct protocol_params_t;

int dummy_init(int n_options, char **options, struct protocol_params_t *lsn);
void *dummy_new(struct protocol_t *proto_struct,
                struct protocol_params_t *params);

#endif
