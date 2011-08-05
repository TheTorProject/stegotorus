/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "steg.h"

#include <event2/buffer.h>

/* This is an example steganography module.  Don't use it to disguise real
   traffic!  It packages client->server traffic as HTTP GET requests and
   server->client traffic as HTTP responses, but makes no actual attempt
   to obscure the data proper. */

struct x_http_steg_t
{
  steg_t super;
  /* no extra stuff is presently necessary */
};

STEG_DEFINE_MODULE(x_http,
                   1024,  /* client-server max data rate - made up */
                   10240, /* server-client max data rate - ditto */
                   1,     /* max concurrent connections per IP */
                   1);     /* max concurrent IPs */

/* Canned HTTP query and response headers. */
static const char http_query_1[] =
  "GET /";
static const char http_query_2[] =
  " HTTP/1.1\r\n"
  "Host: ";
static const char http_query_3[] =
  "\r\n"
  "Connection: close\r\n\r\n";

static const char http_response_1[] =
  "HTTP/1.1 200 OK\r\n"
  "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
  "Cache-Control: no-store\r\n"
  "Connection: close\r\n"
  "Content-Type: application/octet-stream\r\n"
  "Content-Length: ";
static const char http_response_2[] =
  "%lu\r\n"
  "\r\n";


steg_t *
x_http_new(rng_t *rng, unsigned int is_clientside)
{
  STEG_NEW(x_http, state, rng, is_clientside);
  /* if there were extra stuff to fill in, you would do it here */
  return upcast_steg(state);
}

void
x_http_del(steg_t *s)
{
  x_http_steg_t *state = downcast_steg(s);
  STEG_DEL(s);
  /* if there were extra stuff to deallocate, you would do it here */
  free(state);
}

unsigned int
x_http_detect(conn_t *conn)
{
  struct evbuffer *buf = conn_get_inbound(conn);
  unsigned char *data;

  /* Look for the text of http_response_1. */
  if (evbuffer_get_length(buf) >= sizeof http_response_1 - 1) {
    data = evbuffer_pullup(buf, sizeof http_response_1 - 1);
    if (!memcmp(data, http_response_1, sizeof http_response_1 - 1))
      return 1;
  }

  /* The client always transmits "GET /" followed by at least four
     characters that are either lowercase hex digits or equals
     signs, so we need nine bytes of incoming data. */
  if (evbuffer_get_length(buf) >= 9) {
    data = evbuffer_pullup(buf, 9);
    if (!memcmp(data, "GET /", 5) &&
        (ascii_isxdigit(data[5]) || data[5] == '=') &&
        (ascii_isxdigit(data[6]) || data[6] == '=') &&
        (ascii_isxdigit(data[7]) || data[7] == '=') &&
        (ascii_isxdigit(data[8]) || data[8] == '='))
      return 1;
  }

  /* Didn't find either the client or the server pattern. */
  return 0;
}

size_t
x_http_transmit_room(steg_t *s, conn_t *conn)
{
  if (s->is_clientside)
    /* per http://www.boutell.com/newfaq/misc/urllength.html,
       IE<9 can handle no more than 2048 characters in the path
       component of a URL; we're not talking to IE, but this limit
       means longer paths look fishy; we hex-encode the path, so
       we have to cut the number in half. */
    return 1024;
  else
    /* no practical limit applies */
    return SIZE_MAX;
}

int
x_http_transmit(steg_t *s, struct evbuffer *source, conn_t *conn)
{
  struct evbuffer *dest = conn_get_outbound(conn);

  if (s->is_clientside) {
    /* On the client side, we have to embed the data in a GET query somehow;
       the only plausible places to put it are the URL and cookies.  This
       presently uses the URL. And it can't be binary. */
    struct evbuffer *scratch = evbuffer_new();

    /* Convert all the data in 'source' to hexadecimal and write it to
       'scratch'. Data is padded to a multiple of four characters with
       equals signs. */
    size_t slen = evbuffer_get_length(source);
    size_t dlen = slen * 2;

    dlen = dlen + 3 - (dlen-1)%4;
    if (dlen == 0) dlen = 4;

    if (evbuffer_expand(scratch, dlen)) {
      evbuffer_free(scratch);
      return -1;
    }

    /* XXX Failures past this point consume data in 'source'. */
    while (evbuffer_get_length(source) > 0) {
      size_t chunk = evbuffer_get_contiguous_space(source);
      unsigned char *data = evbuffer_pullup(source, chunk);
      char hex[2], c;
      size_t i;
      for (i = 0; i < chunk; i++) {
        c = data[i];
        hex[0] = "0123456789abcdef"[(c & 0xF0) >> 4];
        hex[1] = "0123456789abcdef"[(c & 0x0F) >> 0];
        evbuffer_add(scratch, hex, 2);
      }
      evbuffer_drain(source, chunk);
    }
    while (evbuffer_get_length(scratch) == 0 ||
           evbuffer_get_length(scratch) % 4 != 0)
      evbuffer_add(scratch, "=", 1);

    if (evbuffer_add(dest, http_query_1, sizeof http_query_1-1) ||
        evbuffer_add_buffer(dest, scratch) ||
        evbuffer_add(dest, http_query_2, sizeof http_query_2-1) ||
        evbuffer_add(dest, conn->peername, strlen(conn->peername)) ||
        evbuffer_add(dest, http_query_3, sizeof http_query_3-1)) {
      evbuffer_free(scratch);
      return -1;
    }

    evbuffer_free(scratch);
    conn_cease_transmission(conn);
    return 0;

  } else {
    /* On the server side, we just fake up some HTTP response headers and
       then splat the data we were given. Binary is OK. */

    if (evbuffer_add(dest, http_response_1, sizeof http_response_1-1))
        return -1;
    if (evbuffer_add_printf(dest, http_response_2,
                            (unsigned long)evbuffer_get_length(source)) == -1)
      return -1;
    if (evbuffer_add_buffer(dest, source))
      return -1;

    conn_close_after_transmit(conn);
    return 0;
  }
}

enum recv_ret
x_http_receive(steg_t *s, conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn_get_inbound(conn);
  if (s->is_clientside) {
    /* Linearize the buffer out past the longest possible
       Content-Length header and subsequent blank line.  2**64 fits in
       20 characters, and then we have two CRLFs; minus one for the
       NUL in sizeof http_response_1. Note that this does _not_
       guarantee that that much data is available. */

    unsigned char *data = evbuffer_pullup(source, sizeof http_response_1 + 23);
    size_t hlen = evbuffer_get_length(source);
    if (hlen > sizeof http_response_1 + 23)
      hlen = sizeof http_response_1 + 23;

    /* Validate response headers. */
    if (hlen < sizeof http_response_1 - 1)
      return RECV_INCOMPLETE;
    if (memcmp(data, http_response_1, sizeof http_response_1 - 1))
      return RECV_BAD;

    /* There should be an unsigned number immediately after the text of
       http_response_1, followed by the four characters \r\n\r\n.
       We may not have the complete number yet. */
    unsigned char *p = data + sizeof http_response_1 - 1;
    unsigned char *limit = data + hlen;
    uint64_t clen = 0;
    while (p < limit && '0' <= *p && *p <= '9') {
      clen = clen*10 + *p - '0';
      p++;
    }
    if (p+4 > limit)
      return RECV_INCOMPLETE;
    if (p[0] != '\r' || p[1] != '\n' || p[2] != '\r' || p[3] != '\n')
      return RECV_BAD;

    p += 4;
    hlen = p - data;
    /* Now we know how much data we're expecting after the blank line. */
    if (evbuffer_get_length(source) < hlen + clen)
      return RECV_INCOMPLETE;
    if (evbuffer_get_length(source) > hlen + clen)
      return RECV_BAD;

    /* we are go */
    if (evbuffer_drain(source, hlen))
      return RECV_BAD;

    if (evbuffer_remove_buffer(source, dest, clen) != clen)
      return RECV_BAD;

    conn_expect_close(conn);
    return RECV_GOOD;
  } else {
    /* Search for the second and third invariant bits of the query headers
       we expect.  We completely ignore the contents of the Host header. */
    struct evbuffer_ptr s2 = evbuffer_search(source, http_query_2,
                                             sizeof http_query_2 - 1,
                                             NULL);
    if (s2.pos == -1) {
      log_debug("Did not find second piece of HTTP query");
      return RECV_INCOMPLETE;
    }
    struct evbuffer_ptr s3 = evbuffer_search(source, http_query_3,
                                             sizeof http_query_3 - 1,
                                             &s2);
    if (s3.pos == -1) {
      log_debug("Did not find third piece of HTTP query");
      return RECV_INCOMPLETE;
    }
    if (s3.pos + sizeof http_query_3 - 1 != evbuffer_get_length(source)) {
      log_debug("Unexpected HTTP query body");
      return RECV_BAD;
    }

    unsigned char *data = evbuffer_pullup(source, s2.pos);
    if (memcmp(data, "GET /", sizeof "GET /"-1)) {
      log_debug("Unexpected HTTP verb: %.*s", 5, data);
      return RECV_BAD;
    }

    unsigned char *p = data + sizeof "GET /"-1;
    unsigned char *limit = data + s2.pos;

    /* We need a scratch buffer here because the contract is that if
       we hit a decode error we *don't* write anything to 'dest'. */
    struct evbuffer *scratch = evbuffer_new();
    if (evbuffer_expand(scratch, (limit - p)/2)) {
      evbuffer_free(scratch);
      return RECV_BAD;
    }

    unsigned char c, h, secondhalf = 0;
    while (p < limit) {
      if (!secondhalf) c = 0;
      if ('0' <= *p && *p <= '9') h = *p - '0';
      else if ('a' <= *p && *p <= 'f') h = *p - 'a' + 10;
      else if ('A' <= *p && *p <= 'F') h = *p - 'A' + 10;
      else if (*p == '=' && !secondhalf) {
        p++;
        continue;
      } else {
        evbuffer_free(scratch);
        log_debug("Decode error: unexpected URI character %c", *p);
        return RECV_BAD;
      }

      c = (c << 4) + h;
      if (secondhalf)
        evbuffer_add(scratch, &c, 1);
      secondhalf = !secondhalf;
      p++;
    }

    if (evbuffer_add_buffer(dest, scratch)) {
      evbuffer_free(scratch);
      log_debug("Failed to transfer buffer");
      return RECV_BAD;
    } else {
      evbuffer_drain(source, evbuffer_get_length(source));
      evbuffer_free(scratch);
      conn_transmit_soon(conn, 100);
      return RECV_GOOD;
    }
  }
}
