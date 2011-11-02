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

#include <event2/buffer.h>
#include <stdio.h>






#define MIN_COOKIE_SIZE 128
#define MAX_COOKIE_SIZE 2048


int 
x_http2_server_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

int
lookup_peer_name_from_ip(char* p_ip, char* p_name);


static int has_peer_name = 0;
static char peername[512];


struct x_http2_steg_t
{
  steg_t super;
  
  int have_transmitted;
  int have_received;
  int type;
};


STEG_DEFINE_MODULE(x_http2,
                   1024,  /* client-server max data rate - made up */
                   10240, /* server-client max data rate - ditto */
                   1,     /* max concurrent connections per IP */
                   1);     /* max concurrent IPs */






int x_http2_client_transmit (steg_t *s, struct evbuffer *source, conn_t *conn);

void evbuffer_dump(struct evbuffer *buf, FILE *out);
void buf_dump(unsigned char* buf, int len, FILE *out);



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
    p = v[i].iov_base;
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





steg_t * 
x_http2_new(rng_t *rng, unsigned int is_clientside)
{

  STEG_NEW(x_http2, state, rng, is_clientside);

  if (is_clientside)
    load_payloads("traces/client.out");
  else {
    load_payloads("traces/server.out");
    init_JS_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, JS_MIN_AVAIL_SIZE);
    init_HTML_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, HTML_MIN_AVAIL_SIZE);
    //    init_PDF_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, PDF_MIN_AVAIL_SIZE);
    init_SWF_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, 0);
  }


  /* if there were extra stuff to fill in, you would do it here */
  return upcast_steg(state);
}

void
x_http2_del(steg_t *s)
{
  x_http2_steg_t *state = downcast_steg(s);

  STEG_DEL(s);

  /* if there were extra stuff to deallocate, you would do it here */
  free(state);
}


// x_http2_detect determines if a packet should be processed by the http2 steg module 
unsigned int
x_http2_detect(conn_t *conn)
{
  struct evbuffer *buf = conn_get_inbound(conn);
  unsigned char *data;

  // return 0;
/*****
 Here is a list of HTTP response codes extracted from the server-portals.out trace

7369 HTTP/1.1 200 OK
 470 HTTP/1.1 302 Found
 350 HTTP/1.1 304 Not Modified
 212 HTTP/1.1 302 Moved Temporarily
 184 HTTP/1.1 204 No Content
 451 HTTP/1.0 200 OK
  36 HTTP/1.0 204 No Content
  21 HTTP/1.1 301 Moved Permanently
  19 HTTP/1.1 302 Object moved
  15 HTTP/1.1 404 Not Found

   7 HTTP/1.0 304 Not Modified
   6 HTTP/1.1 302 Redirect
   3 HTTP/1.0 200 Ok
   2 HTTP/1.1 303 Object Moved
   2 HTTP/1.0 301 Moved Permanently
   2 HTTP/1.0 302 Moved Temporarily
   2 HTTP/1.0 400 Bad request
   2 HTTP/1.0 403 Forbidden
   1 HTTP/1.0 404 Not Found
   1 HTTP/1.1 200
   1 HTTP/1.1 302 FOUND
   1 HTTP/1.1 304
   1 HTTP/1.1 400 Bad Request
   1 HTTP/1.1 403 Forbidden
   1 HTTP/1.1 503 Service Unavailable.
 *****/

  // The first part of a valid HTTP response should be of the form
  // HTTP/1.x nnn

  if (evbuffer_get_length(buf) >= 12) {
    data = evbuffer_pullup(buf, 12);
    
    if (data != NULL &&
         ((!memcmp(data, "HTTP/1.1 200", 12)) ||
          (!memcmp(data, "HTTP/1.1 302", 12)) ||
          (!memcmp(data, "HTTP/1.1 304", 12)) ||
          (!memcmp(data, "HTTP/1.1 204", 12)) ||
          (!memcmp(data, "HTTP/1.0 200", 12)) ||
          (!memcmp(data, "HTTP/1.0 204", 12)) ||
          (!memcmp(data, "HTTP/1.1 301", 12)) ||
          (!memcmp(data, "HTTP/1.1 302", 12)) ||
          (!memcmp(data, "HTTP/1.1 404", 12)))) {
      log_debug("x_http2_detect: valid response");
      return 1;
    }
  }





  // SC: if we are only interested in jsSteg, we may want to
  // consider HTTP/1.1 and HTTP/1.0 responses whose code is 200 only

  // check to see if this is a valid HTTP request
  //
  // the following is for HTTP requests used by the http2 steg module
  // The client always transmits "GET /" followed by at least four
  // characters that are either lowercase hex digits or equals
  // signs, so we need nine bytes of incoming data.



  if (evbuffer_get_length(buf) >= 9) {
    data = evbuffer_pullup(buf, 9);
    if (data != NULL && (!memcmp(data, "GET /", 5) || !memcmp(data, "POST /", 5) || !memcmp(data, "Cookie", 6))) {
      log_debug("x_http2_detect: valid request");
      return 1;
    }
  }
 
  log_debug("x_http2_detect: didn't find either HTTP request or response");
  /* Didn't find either the client or the server pattern. */
  return 0;
}

size_t
x_http2_transmit_room(steg_t *s, conn_t *conn)
{
  unsigned int mjc;

  if (downcast_steg(s)->have_transmitted)
    /* can't send any more on this connection */
    return 0;
  

  if (s->is_clientside) {
    /* per http://www.boutell.com/newfaq/misc/urllength.html,
       IE<9 can handle no more than 2048 characters in the path
       component of a URL; we're not talking to IE, but this limit
       means longer paths look fishy; we hex-encode the path, so
       we have to cut the number in half. */
    return (MIN_COOKIE_SIZE + rand() % (MAX_COOKIE_SIZE - MIN_COOKIE_SIZE)) / 4;
    // return 1024;
  } 
  else {

    if (!downcast_steg(s)->have_received)
      return 0;

    switch(downcast_steg(s)->type) {

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
x_http2_client_transmit (steg_t *s, struct evbuffer *source, conn_t *conn) {

  /* On the client side, we have to embed the data in a GET query somehow;
     the only plausible places to put it are the URL and cookies.  This
     presently uses the URL. And it can't be binary. */
  // struct evbuffer *scratch;
  struct evbuffer_iovec *iv;
  int i, nv;
  struct evbuffer *dest = conn_get_outbound(conn);
  size_t sbuflen = evbuffer_get_length(source);
  char buf[10000];
  unsigned char data[(int) sbuflen*2];
  //  unsigned char outbuf[MAX_COOKIE_SIZE];

  unsigned char outbuf[(int) sbuflen*8];
  int datalen;


  //  size_t sofar = 0;
  size_t cookie_len;
  

  /* Convert all the data in 'source' to hexadecimal and write it to
     'scratch'. Data is padded to a multiple of four characters with
     equals signs. */


  unsigned int len = 0;
  unsigned int cnt = 0;



  datalen = 0;    
  cookie_len = 4 * sbuflen + rand() % 4;
  

  nv = evbuffer_peek(source, sbuflen, NULL, NULL, 0);
  iv = xzalloc(sizeof(struct evbuffer_iovec) * nv);

  if (evbuffer_peek(source, sbuflen, NULL, iv, nv) != nv) {
    free(iv);
    return -1;
  }

  // retry up to 10 times
  while (!len) {
    len = find_client_payload(buf, sizeof(buf), TYPE_HTTP_REQUEST);
    if (cnt++ == 10) return -1;
  }


  if (has_peer_name == 0 && lookup_peer_name_from_ip((char*) conn->peername, peername))
    has_peer_name = 1;

  // if (find_uri_type(buf) != HTTP_CONTENT_SWF) {
  //   fprintf(stderr, "%s\n", buf);
  //   exit(-1);
  // }
    

  
  cnt = 0;
  
  for (i = 0; i < nv; i++) {
    const unsigned char *p = iv[i].iov_base;
    const unsigned char *limit = p + iv[i].iov_len;
    char c;
    while (p < limit && cnt < sbuflen) {
      c = *p++;
      data[datalen] = "0123456789abcdef"[(c & 0xF0) >> 4];
      data[datalen+1] = "0123456789abcdef"[(c & 0x0F) >> 0];
      datalen += 2;
      cnt++;
    }
  }
  
  free(iv);

  if (cookie_len < 4) cookie_len = 4;

  datalen = gen_cookie_field(outbuf, cookie_len, data, datalen);
  log_debug("CLIENT: sending cookie of length = %d %d\n", datalen, (int) cookie_len);
  //  fprintf(stderr, "CLIENT: sending cookie of length = %d %d\n", datalen, (int) cookie_len);

  if (datalen < 0) {
    log_debug("cookie generation failed\n");
    return -1;
  }


  if (evbuffer_add(dest, buf, strstr(buf, "\r\n") - buf + 2)  ||  // add uri field
      evbuffer_add(dest, "Host: ", 6) ||
      evbuffer_add(dest, peername, strlen(peername)) ||
      evbuffer_add(dest, strstr(buf, "\r\n"), len - (unsigned int) (strstr(buf, "\r\n") - buf))  ||  // add everything but first line
      evbuffer_add(dest, "Cookie: ", 8) ||
      evbuffer_add(dest, outbuf, cookie_len) ||
      evbuffer_add(dest, "\r\n\r\n", 4)) {
      log_debug("error ***********************");
      return -1;
    }
 
  // debug
  // log_warn("CLIENT HTTP request header:");
  // buf_dump((unsigned char*)buf, len, stderr);
 
  //  sofar += datalen/2;
  evbuffer_drain(source, datalen/2);
  
  log_debug("CLIENT TRANSMITTED payload %d\n", (int) sbuflen);
  
  conn_cease_transmission(conn);

  downcast_steg(s)->type = find_uri_type(buf);
  downcast_steg(s)->have_transmitted = 1;
  return 0;
}




















int
x_http2_transmit(steg_t *s, struct evbuffer *source, conn_t *conn)
{
  //  struct evbuffer *dest = conn_get_outbound(conn);

  //  fprintf(stderr, "in x_http2_ transmit %d\n", downcast_steg(s)->type);
    


  if (s->is_clientside) {
        /* On the client side, we have to embed the data in a GET query somehow;
       the only plausible places to put it are the URL and cookies.  This
       presently uses the URL. And it can't be binary. */

    return x_http2_client_transmit(s, source, conn); //@@
  } 
  else {
    int rval = -1;
    switch(downcast_steg(s)->type) {
      
    case HTTP_CONTENT_SWF: 
      rval = x_http2_server_SWF_transmit(s, source, conn);
      break;

    case HTTP_CONTENT_JAVASCRIPT:
      rval = x_http2_server_JS_transmit(s, source, conn, HTTP_CONTENT_JAVASCRIPT);
      break;

    case HTTP_CONTENT_HTML:
      rval = x_http2_server_JS_transmit(s, source, conn, HTTP_CONTENT_HTML);
      break;

    case HTTP_CONTENT_PDF:
      rval = x_http2_server_PDF_transmit(s, source, conn);
      break;
    }

    if (rval == 0) downcast_steg(s)->have_transmitted = 1;
    return rval;
  }
}






int 
x_http2_server_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source) {

  int cnt = 0;
  unsigned char* data;
  int type;

  do {
    struct evbuffer_ptr s2 = evbuffer_search(source, "\r\n\r\n", sizeof ("\r\n\r\n") -1 , NULL);
    unsigned char* limit;
    unsigned char *p;
    int unwrapped_cookie_len;
    struct evbuffer *scratch;
    unsigned char c, h, secondhalf;
    unsigned char buf[evbuffer_get_length(source)];


    if (s2.pos == -1) {
      log_debug("Did not find end of request %d", (int) evbuffer_get_length(source));
      //      evbuffer_dump(source, stderr);
      return RECV_INCOMPLETE;
    }

    log_debug("SERVER received request header of length %d", (int)s2.pos);

    data = evbuffer_pullup(source, s2.pos);
    if (data == NULL) {
      log_debug("SERVER evbuffer_pullup fails");
      return RECV_BAD;
    }

    limit = data + s2.pos;

    type = find_uri_type((char *)data);
    log_warn ("*** Got type %d", type);

    /*    if (type != 3) {
	  fprintf(stderr, "type != 3, %d, data = %s \n", find_uri_type2((char *) data), data);
	  exit(-1);
	  }*/

    data = (unsigned char*) strstr((char*) data, "Cookie:");

    if (data == NULL || memcmp(data, "Cookie:", sizeof "Cookie:"-1)) {
      log_debug("Unexpected HTTP verb: %.*s", 5, data);
      return RECV_BAD;
    }

    p = data + sizeof "Cookie: "-1;
    unwrapped_cookie_len = unwrap_cookie(p, buf, (int) (limit - p));

    log_debug("SERVER: received cookie of length = %d %d\n", unwrapped_cookie_len, (int) (limit-p));
    //    buf_dump(buf, unwrapped_cookie_len, stderr);
    //    fprintf(stderr, "==========================\n");
    //    buf_dump(p, (int) (limit-p), stderr);

    
    //    log_debug("hello SERVER received %d cnt = %d\n", (int) (limit - p), cnt);
    //     buf_dump(p, (int) (limit-p), stderr);

    /* We need a scratch buffer here because the contract is that if
       we hit a decode error we *don't* write anything to 'dest'. */
    scratch = evbuffer_new();

    if (!scratch) return RECV_BAD;


    if (evbuffer_expand(scratch, unwrapped_cookie_len/2)) {
      log_debug("Evbuffer expand failed \n");
      evbuffer_free(scratch);
      return RECV_BAD;
    }
    p = buf;


    secondhalf = 0;
    while ((int) (p - buf) < unwrapped_cookie_len) {
      if (!secondhalf) c = 0;
      if ('0' <= *p && *p <= '9') h = *p - '0';
      else if ('a' <= *p && *p <= 'f') h = *p - 'a' + 10;
      else if ('A' <= *p && *p <= 'F') h = *p - 'A' + 10;
      else if (*p == '=' && !secondhalf) {
	p++;
	continue;
      } else {
	evbuffer_free(scratch);
	log_debug("Decode error: unexpected URI characterasdfaf %d", *p);
	return RECV_BAD;
      }

      c = (c << 4) + h;
      if (secondhalf) {
	evbuffer_add(scratch, &c, 1);
	//	log_debug("adding to scratch");
	cnt++;
      }
      secondhalf = !secondhalf;
      p++;
    }



    if (evbuffer_add_buffer(dest, scratch)) {
      evbuffer_free(scratch);
      log_debug("Failed to transfer buffer");
      return RECV_BAD;
    } 
    evbuffer_drain(source, s2.pos + sizeof("\r\n\r\n") - 1);
    evbuffer_free(scratch);
  } while (evbuffer_get_length(source));
  

  downcast_steg(s)->have_received = 1;
  downcast_steg(s)->type = type;
  //  fprintf(stderr, "SERVER RECEIVED payload %d %d\n", cnt, type);
    
  conn_transmit_soon(conn, 100);
  return RECV_GOOD;
}








static int
x_http2_receive(steg_t *s, conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn_get_inbound(conn);
  // unsigned int type;
  int rval = RECV_BAD;


  if (s->is_clientside) {

    //    fprintf(stderr, "client type = %d\n", downcast_steg(s)->type);

    switch(downcast_steg(s)->type) {
      
    case HTTP_CONTENT_SWF: 
      rval = x_http2_handle_client_SWF_receive(s, conn, dest, source);
      break;

    case HTTP_CONTENT_JAVASCRIPT:
    case HTTP_CONTENT_HTML:
      rval = x_http2_handle_client_JS_receive(s, conn, dest, source);
      break;

    case HTTP_CONTENT_PDF:
      rval = x_http2_handle_client_PDF_receive(s, conn, dest, source);
      break;
    }

    if (rval == RECV_GOOD) downcast_steg(s)->have_received = 1;
    return rval;

  } else {
    return x_http2_server_receive(s, conn, dest, source);
  }

   
}
