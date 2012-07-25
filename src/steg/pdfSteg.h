/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _PDFSTEG_H
#define _PDFSTEG_H

// These are the public interface.

int http_server_PDF_transmit(PayloadServer* pl, struct evbuffer *source,
                             conn_t *conn);
int http_handle_client_PDF_receive(steg_t *s, conn_t *conn,
                                   struct evbuffer *dest,
                                   struct evbuffer* source);

// These are exposed only for the sake of unit tests.

ssize_t pdf_add_delimiter(const char *inbuf, size_t inbuflen,
                          char *outbuf, size_t outbuflen,
                          char delimiter1, char delimiter2);

ssize_t pdf_remove_delimiter(const char *inbuf, size_t inbuflen,
                             char *outbuf, size_t outbuflen,
                             char delimiter1, bool *endFlag, bool *escape);

ssize_t pdf_wrap(const char *data, size_t dlen,
                 const char *pdfTemplate, size_t plen,
                 char *outbuf, size_t outbufsize);

ssize_t pdf_unwrap(const char *data, size_t dlen,
                   char *outbuf, size_t outbufsize);

#endif
