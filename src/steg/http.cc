/*  Copyright (c) 2011, SRI International

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

    * Neither the names of the copyright owners nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Contributors: Zack Weinberg, Vinod Yegneswaran
    See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "steg.h"
#include "payloads.h"
#include "cookies.h"
#include "swfSteg.h"
#include "pdfSteg.h"
#include "jsSteg.h"
#include "b64cookies.h"

#include <event2/buffer.h>
#include <stdio.h>

#define MIN_COOKIE_SIZE 24
#define MAX_COOKIE_SIZE 1024

int
http_server_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

int
lookup_peer_name_from_ip(char* p_ip, char* p_name);


static int has_peer_name = 0;
static char peername[512];

namespace {
struct http : steg_t
{
  bool have_transmitted : 1;
  bool have_received : 1;
  int type;

  STEG_DECLARE_METHODS(http);
};
}

STEG_DEFINE_MODULE(http);

int http_client_uri_transmit (steg_t *s, struct evbuffer *source, conn_t *conn);
int http_client_cookie_transmit (steg_t *s, struct evbuffer *source, conn_t *conn);

void evbuffer_dump(struct evbuffer *buf, FILE *out);
void buf_dump(unsigned char* buf, int len, FILE *out);
int gen_uri_field(char* uri, unsigned int uri_sz, char* data, int datalen);


void
evbuffer_dump(struct evbuffer *buf, FILE *out)
{
  int nextent = evbuffer_peek(buf, SSIZE_MAX, 0, 0, 0);
  struct evbuffer_iovec v[nextent];
  int i;
  const unsigned char *p, *limit;

  if (evbuffer_peek(buf, -1, 0, v, nextent) != nextent)
    abort();

  for (i = 0; i < nextent; i++) {
    p = (const unsigned char *)v[i].iov_base;
    limit = p + v[i].iov_len;

    putc('|', out);
    while (p < limit) {
      if (*p < 0x20 || *p >= 0x7F || *p == '\\' || *p == '|')
        fprintf(out, "\\x%02x", *p);
      else
        putc(*p, out);
      p++;
    }
  }
  putc('|', out);
}





void
buf_dump(unsigned char* buf, int len, FILE *out)
{
  int i=0;
  putc('|', out);
  while (i < len) {
    if (buf[i] < 0x20 || buf[i] >= 0x7F || buf[i] == '\\' || buf[i]== '|')
      fprintf(out, "\\x%02x", buf[i]);
    else
      putc(buf[i], out);
    i++;
  }
  putc('|', out);
  putc('\n', out);
}


http::http(bool is_clientside)
  : steg_t(is_clientside),
    have_transmitted(false), have_received(false)
{
  if (is_clientside)
    load_payloads("traces/client.out");
  else {
    load_payloads("traces/server.out");
    init_JS_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, JS_MIN_AVAIL_SIZE);
    //   init_JS_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, JS_MIN_AVAIL_SIZE, HTTP_CONTENT_HTML);
    init_HTML_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, HTML_MIN_AVAIL_SIZE);
    init_PDF_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, PDF_MIN_AVAIL_SIZE);
    init_SWF_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, 0);
  }
}

http::~http()
{
}

size_t
http::transmit_room(conn_t *)
{
  unsigned int mjc;

  if (have_transmitted)
    /* can't send any more on this connection */
    return 0;


  if (is_clientside) {
    return (MIN_COOKIE_SIZE + rand() % (MAX_COOKIE_SIZE - MIN_COOKIE_SIZE)) / 4;
  }
  else {

    if (!have_received)
      return 0;

    switch (type) {

    case HTTP_CONTENT_SWF:
      return 1024;

    case HTTP_CONTENT_JAVASCRIPT:
      mjc = get_max_JS_capacity() / 2;
      if (mjc > 1024) {
        // it should be 1024 + ...., but seems like we need to be a little bit smaller (chopper bug?)
        int rval = 512 + rand()%(mjc - 1024);
        //	fprintf(stderr, "returning rval %d, mjc  %d\n", rval, mjc);
        return rval;
      }
      log_warn("js capacity too small\n");
      exit(-1);

    case HTTP_CONTENT_HTML:
      mjc = get_max_HTML_capacity() / 2;
      if (mjc > 1024) {
        // it should be 1024 + ...., but seems like we need to be a little bit smaller (chopper bug?)
        int rval = 512 + rand()%(mjc - 1024);
        //	fprintf(stderr, "returning rval %d, mjc  %d\n", rval, mjc);
        return rval;
      }
      log_warn("js capacity too small\n");
      exit(-1);

    case HTTP_CONTENT_PDF:
      // return 1024 + rand()%(get_max_PDF_capacity() - 1024)
      return PDF_MIN_AVAIL_SIZE;
    }

    return SIZE_MAX;
  }
}






int
lookup_peer_name_from_ip(char* p_ip, char* p_name)  {
  struct addrinfo* ailist;
  struct addrinfo* aip;
  struct addrinfo hint;
  char buf[128];

  hint.ai_flags = AI_CANONNAME;
  hint.ai_family = 0;
  hint.ai_socktype = 0;
  hint.ai_protocol = 0;
  hint.ai_addrlen = 0;
  hint.ai_canonname = NULL;
  hint.ai_addr = NULL;
  hint.ai_next = NULL;

  strcpy(buf, p_ip);
  buf[strchr(buf, ':') - buf] = 0;


  if (getaddrinfo(buf, NULL, &hint, &ailist)) {
    fprintf(stderr, "error: getaddrinfo() %s\n", p_ip);
    exit(1);
  }

  for (aip = ailist; aip != NULL; aip = aip->ai_next) {
    char buf[512];
    if (getnameinfo(aip->ai_addr, sizeof(struct sockaddr), buf, 512, NULL, 0, 0) == 0) {
      sprintf(p_name, "%s", buf);
      return 1;
    }
  }

  return 0;
}








int
http_client_cookie_transmit (http *s, struct evbuffer *source, conn_t *conn) {

  /* On the client side, we have to embed the data in a GET query somehow;
     the only plausible places to put it are the URL and cookies.  This
     presently uses the URL. And it can't be binary. */


  struct evbuffer *dest = conn->outbound();
  size_t sbuflen = evbuffer_get_length(source);
  int bufsize = 10000;
  char* buf = (char*) xmalloc(bufsize);

  char* data;
  char* data2 = (char*) xmalloc (sbuflen*4);
  char* cookiebuf = (char*) xmalloc (sbuflen*8);
  int payload_len = 0;
  int cnt = 0;
  int cookie_len = 0;
  int rval;
  int len = 0;
  base64::encoder E;



  data = (char*) evbuffer_pullup(source, sbuflen);

  if (data == NULL) {
    log_debug("evbuffer_pullup failed");
    goto err;
  }



  // retry up to 10 times
  while (!payload_len) {
    payload_len = find_client_payload(buf, bufsize, TYPE_HTTP_REQUEST);
    if (cnt++ == 10) {
      goto err;
    }
  }
  buf[payload_len] = 0;

  if (has_peer_name == 0 && lookup_peer_name_from_ip((char*) conn->peername, peername))
    has_peer_name = 1;


  bzero(data2, sbuflen*4);
  E.encode((char*) data, sbuflen, (char*) data2);
  E.encode_end(data2+strlen((char*) data2));

  len = (int) strlen(data2) - 1;
    // remove trailing newline
  data2[len] = 0;
  
  // substitute / with _, + with ., = with - that maybe inserted anywhere in the middle 
  sanitize_b64(data2, len);

  
  cookie_len = gen_b64_cookie_field(cookiebuf, data2, len);
  cookiebuf[cookie_len] = 0;



  if (cookie_len < 0) {
    log_debug("cookie generation failed\n");
    return -1;
  }
  

  // add uri field
  rval = evbuffer_add(dest, buf, strstr(buf, "\r\n") - buf + 2);
  if (rval) {
    log_warn("error adding uri field\n");
    goto err;
  }

  rval = evbuffer_add(dest, "Host: ", 6);
  if (rval) {
    log_warn("error adding host field\n");
    goto err;
  }

  rval = evbuffer_add(dest, peername, strlen(peername));
  if (rval) { 
    log_warn("error adding peername field\n");
    goto err;
  }


  rval = evbuffer_add(dest, strstr(buf, "\r\n"), payload_len - (unsigned int) (strstr(buf, "\r\n") - buf));
  if (rval) {
    log_warn("error adding HTTP fields\n");
    goto err;
  }

  rval =   evbuffer_add(dest, "Cookie: ", 8);
  if (rval) {
    log_warn("error adding cookie fields\n");
    goto err;
  }
  rval = evbuffer_add(dest, cookiebuf, cookie_len);

  if (rval) {
    log_warn("error adding cookie buf\n");
    goto err;
  }


  rval = evbuffer_add(dest, "\r\n\r\n", 4);
							     
  if (rval) {
    log_warn("error adding terminators \n");
    goto err;
  }

  

  evbuffer_drain(source, sbuflen);
  log_debug("CLIENT TRANSMITTED payload %d\n", (int) sbuflen);
  conn_cease_transmission(conn);

  s->type = find_uri_type(buf, bufsize);
  s->have_transmitted = true;


  free(buf);
  free(data2);
  return 0;

err:
  free(buf);
  free(data2);
  return -1;

}




int gen_uri_field(char* uri, unsigned int uri_sz, char* data, int datalen) {
  unsigned int so_far = 0;
  uri[0] = 0;

  strcat(uri, "GET /");
  so_far = 5;

  while (datalen > 0) {
    unsigned int r = rand() % 4;

    if (r == 1) {
      r = rand() % 46;
      if (r < 20)
        uri[so_far++] = 'g' + r;
      else
        uri[so_far++] = 'A' + r - 20;
    }
    else {
      uri[so_far++] = data[0];
      data++;
      datalen--;
    }



    r = rand() % 8;

    if (r == 0 && datalen > 0)
      uri[so_far++] = '/';

    if (r == 2 && datalen > 0)
      uri[so_far++] = '_';


    if (so_far > uri_sz - 6) {
      fprintf(stderr, "too small\n");
      return 0;
    }
  }

  switch(rand()%4){
  case 1:
    memcpy(uri+so_far, ".htm ", 6);
    break;
  case 2:
    memcpy(uri+so_far, ".html ", 7);
    break;
  case 3:
    memcpy(uri+so_far, ".js ", 5);
    break;
  case 0:
    memcpy(uri+so_far, ".swf ", 6);
    break;

  }

  return strlen(uri);

}





int
http_client_uri_transmit (http *s, struct evbuffer *source, conn_t *conn) {


  struct evbuffer *dest = conn->outbound();


  struct evbuffer_iovec *iv;
  int i, nv;

  /* Convert all the data in 'source' to hexadecimal and write it to
     'scratch'. Data is padded to a multiple of four characters with
     equals signs. */
  size_t slen = evbuffer_get_length(source);
  size_t datalen = 0;
  int cnt = 0;
  char data[2*slen];

  char outbuf[1024];
  int len =0;
  char buf[10000];


  if (has_peer_name == 0 && lookup_peer_name_from_ip((char*) conn->peername, peername))
    has_peer_name = 1;



  nv = evbuffer_peek(source, slen, NULL, NULL, 0);
  iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);
  if (evbuffer_peek(source, slen, NULL, iv, nv) != nv) {
    free(iv);
    return -1;
  }

  for (i = 0; i < nv; i++) {
    const unsigned char *p = (const unsigned char *)iv[i].iov_base;
    const unsigned char *limit = p + iv[i].iov_len;
    char c;
    while (p < limit) {
      c = *p++;
      data[datalen++] = "0123456789abcdef"[(c & 0xF0) >> 4];
      data[datalen++] = "0123456789abcdef"[(c & 0x0F) >> 0];
      }
  }
  free(iv);



  do {
    datalen = gen_uri_field(outbuf, sizeof(outbuf), data, datalen);
  } while (datalen == 0);




  // retry up to 10 times
  while (!len) {
    len = find_client_payload(buf, sizeof(buf), TYPE_HTTP_REQUEST);
    if (cnt++ == 10) return -1;
  }


  //  fprintf(stderr, "outbuf = %s\n", outbuf);

  if (evbuffer_add(dest, outbuf, datalen)  ||  // add uri field
      evbuffer_add(dest, "HTTP/1.1\r\nHost: ", 19) ||
      evbuffer_add(dest, peername, strlen(peername)) ||
      evbuffer_add(dest, strstr(buf, "\r\n"), len - (unsigned int) (strstr(buf, "\r\n") - buf))  ||  // add everything but first line
      evbuffer_add(dest, "\r\n", 2)) {
      log_debug("error ***********************");
      return -1;
  }



  evbuffer_drain(source, slen);
  conn_cease_transmission(conn);
  s->type = find_uri_type(outbuf, sizeof(outbuf));
  s->have_transmitted = 1;
  return 0;

}




















int
http::transmit(struct evbuffer *source, conn_t *conn)
{
  //  struct evbuffer *dest = conn_get_outbound(conn);

  //  fprintf(stderr, "in http_ transmit %d\n", downcast_steg(s)->type);



  if (is_clientside) {
        /* On the client side, we have to embed the data in a GET query somehow;
	   the only plausible places to put it are the URL and cookies.  */

    /*    if (evbuffer_get_length(source) < 72)
      return http_client_uri_transmit(this, source, conn);
    */

 //@@
    return http_client_cookie_transmit(this, source, conn); //@@
  }
  else {
    int rval = -1;
    switch(type) {

    case HTTP_CONTENT_SWF:
      rval = http_server_SWF_transmit(this, source, conn);
      break;

    case HTTP_CONTENT_JAVASCRIPT:
      rval = http_server_JS_transmit(this, source, conn, HTTP_CONTENT_JAVASCRIPT);
      break;

    case HTTP_CONTENT_HTML:
      rval = http_server_JS_transmit(this, source, conn, HTTP_CONTENT_HTML);
      break;

    case HTTP_CONTENT_PDF:
      rval = http_server_PDF_transmit(this, source, conn);
      break;
    }

    if (rval == 0) have_transmitted = 1;
    return rval;
  }
}






int
http_server_receive(http *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source) {

  char* data;
  int type;

  do {
    struct evbuffer_ptr s2 = evbuffer_search(source, "\r\n\r\n", sizeof ("\r\n\r\n") -1 , NULL);
    char *p;
    char *pend;

    char outbuf[MAX_COOKIE_SIZE];
    char outbuf2[MAX_COOKIE_SIZE];
    int sofar = 0;
    //int cookie_mode = 0;


    if (s2.pos == -1) {
      log_debug("Did not find end of request %d", (int) evbuffer_get_length(source));
      //      evbuffer_dump(source, stderr);
      return RECV_INCOMPLETE;
    }

    log_debug("SERVER received request header of length %d", (int)s2.pos);

    data = (char*) evbuffer_pullup(source, s2.pos+4);

    if (data == NULL) {
      log_debug("SERVER evbuffer_pullup fails");
      return RECV_BAD;
    }


    data[s2.pos+3] = 0;

    type = find_uri_type((char *)data, s2.pos+4);

    if (strstr((char*) data, "Cookie") != NULL) {
      p = strstr((char*) data, "Cookie:") + sizeof "Cookie: "-1;
      //cookie_mode = 1;
    }
    else
      p = data + sizeof "GET /" -1;

    pend = strstr(p, "\r\n");

    if (pend == NULL || (pend - p > MAX_COOKIE_SIZE)) {
      fprintf(stderr, "incorrect cookie recovery \n");
      exit(-1);
      
    }



    bzero(outbuf, sizeof(outbuf));
    int cookielen = unwrap_b64_cookie((char*) p, (char*) outbuf, pend - p);


    desanitize_b64(outbuf, cookielen);
    outbuf[cookielen] = '\n';
    bzero(outbuf2, sizeof(outbuf2));

    base64::decoder D;
    sofar = D.decode(outbuf, cookielen+1, outbuf2);


    if (sofar <= 0) 
      log_warn("decode failed\n"); 
      

    if (sofar >= MAX_COOKIE_SIZE) {
      log_warn("cookie buffer overflow????\n"); 
       exit(-1);
    }


    if (evbuffer_add(dest, outbuf2, sofar)) {
      log_debug("Failed to transfer buffer");
      return RECV_BAD;
    }
    evbuffer_drain(source, s2.pos + sizeof("\r\n\r\n") - 1);
  } while (evbuffer_get_length(source));


  s->have_received = 1;
  s->type = type;

  conn_transmit_soon(conn, 100);
  return RECV_GOOD;
}











int
http::receive(conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();
  // unsigned int type;
  int rval = RECV_BAD;


  if (is_clientside) {
    switch(type) {

    case HTTP_CONTENT_SWF:
      rval = http_handle_client_SWF_receive(this, conn, dest, source);
      break;

    case HTTP_CONTENT_JAVASCRIPT:
    case HTTP_CONTENT_HTML:
      rval = http_handle_client_JS_receive(this, conn, dest, source);
      break;

    case HTTP_CONTENT_PDF:
      rval = http_handle_client_PDF_receive(this, conn, dest, source);
      break;
    }

    if (rval == RECV_GOOD) have_received = 1;
    return rval;

  } else {
    return http_server_receive(this, conn, dest, source);
  }


}
