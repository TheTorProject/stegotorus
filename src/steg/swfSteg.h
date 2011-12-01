#ifndef _SWFSTEG_H
#define _SWFSTEG_H


#include "util.h"
#include "connections.h"
#include "steg.h"
#include "payloads.h"
#include "cookies.h"
#include "pdfSteg.h"
#include "zpack.h"


#include <event2/buffer.h>
#include <stdio.h>







#define SWF_SAVE_HEADER_LEN 1500
#define SWF_SAVE_FOOTER_LEN 1500


unsigned int 
swf_wrap(char* inbuf, int in_len, char* outbuf, int out_sz);

unsigned int 
swf_unwrap(char* inbuf, int in_len, char* outbuf, int out_sz);

int 
http_server_SWF_transmit (steg_t* s, struct evbuffer *source, conn_t *conn);


int
http_handle_client_SWF_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

#endif


