#ifndef _PDFSTEG_H
#define _PDFSTEG_H


#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "util.h"
#include "connections.h"
#include "steg.h"
#include <event2/buffer.h>



#define PDF_DELIMITER    '?'
#define PDF_DELIMITER2   '.'

int pdfWrap (char *data, unsigned int dlen, char *pdfTemplate, unsigned int plen, char *outbuf, unsigned int outbufsize);
int pdfUnwrap (char *data, unsigned int dlen, char *outbuf, unsigned int outbufsize);

int addDelimiter(char *inbuf, int inbuflen, char *outbuf, int outbuflen, const char delimiter1, const char delimiter2);
int removeDelimiter(char *inbuf, int inbuflen, char *outbuf, int outbuflen, const char delimiter1, int* endFlag, int* escape);

int http_server_PDF_transmit (steg_t* s, struct evbuffer *source, conn_t *conn);
int
http_handle_client_PDF_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

#endif

