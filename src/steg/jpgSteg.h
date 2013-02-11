/* 
 * Author: Parsaa
 */

#ifndef _JPGSTEG_H
#define _JPGSTEG_H

struct payloads;

int
http_server_JPG_transmit(PayloadServer* pl, struct evbuffer *source, conn_t *conn);

int
http_handle_client_JPG_receive(steg_t *s, conn_t *conn, struct evbuffer *dest,
                               struct evbuffer* source);

#endif
