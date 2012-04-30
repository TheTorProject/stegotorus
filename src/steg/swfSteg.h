/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _SWFSTEG_H
#define _SWFSTEG_H

struct payloads;

#define SWF_SAVE_HEADER_LEN 1500
#define SWF_SAVE_FOOTER_LEN 1500

unsigned int
swf_wrap(payloads& pl, char* inbuf, int in_len, char* outbuf, int out_sz);

unsigned int
swf_unwrap(char* inbuf, int in_len, char* outbuf, int out_sz);

int
http_server_SWF_transmit(payloads& pl, struct evbuffer *source, conn_t *conn);

int
http_handle_client_SWF_receive(steg_t *s, conn_t *conn, struct evbuffer *dest,
                               struct evbuffer* source);

#endif
