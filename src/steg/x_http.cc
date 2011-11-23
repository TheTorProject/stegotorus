/* Copyright 2011 Zack Weinberg
   See LICENSE for other credits and copying information
*/

#include "util.h"
#include "connections.h"
#include "steg.h"
#include "crypt.h"

#include <event2/buffer.h>

/* This is an example steganography module.  Don't use it to disguise real
   traffic!  It packages client->server traffic as HTTP GET requests and
   server->client traffic as HTTP responses, but makes no actual attempt
   to obscure the data proper. */

struct x_http_steg_t
{
  steg_t super;
  int have_transmitted;
  int have_received;
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

static steg_t *
x_http_new(rng_t *rng, unsigned int is_clientside)
{
  STEG_NEW(x_http, state, rng, is_clientside);
  /* if there were extra stuff to fill in, you would do it here */
  return upcast_steg(state);
}

static void
x_http_del(steg_t *s)
{
  x_http_steg_t *state = downcast_steg(s);
  STEG_DEL(s);
  /* if there were extra stuff to deallocate, you would do it here */
  free(state);
}

static unsigned int
x_http_detect(conn_t *conn)
{
  struct evbuffer *buf = conn_get_inbound(conn);
  uint8_t *data;

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

static size_t
x_http_transmit_room(steg_t *s, conn_t *conn)
{
  if (downcast_steg(s)->have_transmitted)
    /* can't send any more on this connection */
    return 0;

  if (s->is_clientside)
    /* per http://www.boutell.com/newfaq/misc/urllength.html,
       IE<9 can handle no more than 2048 characters in the path
       component of a URL; we're not talking to IE, but this limit
       means longer paths look fishy; we hex-encode the path, so
       we have to cut the number in half. */
    return 1024;
  else {
    if (!downcast_steg(s)->have_received)
      return 0;
    /* no practical limit applies */
    return SIZE_MAX;
  }
}

static int
x_http_transmit(steg_t *s, struct evbuffer *source, conn_t *conn)
{
  struct evbuffer *dest = conn_get_outbound(conn);

  if (s->is_clientside) {
    /* On the client side, we have to embed the data in a GET query somehow;
       the only plausible places to put it are the URL and cookies.  This
       presently uses the URL. And it can't be binary. */
    struct evbuffer *scratch;
    struct evbuffer_iovec *iv;
    int i, nv;

    /* Convert all the data in 'source' to hexadecimal and write it to
       'scratch'. Data is padded to a multiple of four characters with
       equals signs. */
    size_t slen = evbuffer_get_length(source);
    size_t dlen = slen * 2;

    dlen = dlen + 3 - (dlen-1)%4;
    if (dlen == 0) dlen = 4;

    scratch = evbuffer_new();
    if (!scratch) return -1;
    if (evbuffer_expand(scratch, dlen)) {
      evbuffer_free(scratch);
      return -1;
    }

    nv = evbuffer_peek(source, slen, NULL, NULL, 0);
    iv = (struct evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);
    if (evbuffer_peek(source, slen, NULL, iv, nv) != nv) {
      evbuffer_free(scratch);
      free(iv);
      return -1;
    }

    for (i = 0; i < nv; i++) {
      const uint8_t *p = (const uint8_t *)iv[i].iov_base;
      const uint8_t *limit = p + iv[i].iov_len;
      char hex[2], c;
      while (p < limit) {
        c = *p++;
        hex[0] = "0123456789abcdef"[(c & 0xF0) >> 4];
        hex[1] = "0123456789abcdef"[(c & 0x0F) >> 0];
        evbuffer_add(scratch, hex, 2);
      }
    }
    free(iv);
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
    evbuffer_drain(source, slen);
    conn_cease_transmission(conn);
    downcast_steg(s)->have_transmitted = 1;
    return 0;

  } else {
    /* On the server side, we just fake up some HTTP response headers
       and then splat the data we were given. Binary is OK.  */
    if (evbuffer_add(dest, http_response_1, sizeof http_response_1-1))
        return -1;
    if (evbuffer_add_printf(dest, "%lu\r\n\r\n",
                            (unsigned long)evbuffer_get_length(source)) == -1)
      return -1;
    if (evbuffer_add_buffer(dest, source))
      return -1;

    conn_close_after_transmit(conn);
    downcast_steg(s)->have_transmitted = 1;
    return 0;
  }
}

static int
x_http_receive(steg_t *s, conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn_get_inbound(conn);
  if (s->is_clientside) {
    /* Linearize the buffer out past the longest possible
       Content-Length header and subsequent blank line.  2**64 fits in
       20 characters, and then we have two CRLFs; minus one for the
       NUL in sizeof http_response_1. Note that this does _not_
       guarantee that that much data is available. */

    size_t hlen = evbuffer_get_length(source);
    uint8_t *data, *p, *limit;
    uint64_t clen;

    log_debug("x_http: %lu byte response stream available%s",
              (unsigned long)hlen,
              hlen >= sizeof http_response_1 - 1 ? "" : " (incomplete)");

    if (downcast_steg(s)->have_received) {
      log_warn("x_http: protocol error: multiple responses");
      return -1;
    }

    if (hlen < sizeof http_response_1 - 1)
      return 0; /* incomplete */

    if (hlen > sizeof http_response_1 + 23)
      hlen = sizeof http_response_1 + 23;

    data = evbuffer_pullup(source, hlen);
    /* Validate response headers. */
    if (memcmp(data, http_response_1, sizeof http_response_1 - 1))
      return -1;

    /* There should be an unsigned number immediately after the text of
       http_response_1, followed by the four characters \r\n\r\n.
       We may not have the complete number yet. */
    p = data + sizeof http_response_1 - 1;
    limit = data + hlen;
    clen = 0;
    while (p < limit && '0' <= *p && *p <= '9') {
      clen = clen*10 + *p - '0';
      p++;
    }
    if (p+4 > limit)
      return 0; /* incomplete */
    if (p[0] != '\r' || p[1] != '\n' || p[2] != '\r' || p[3] != '\n')
      return -1;

    p += 4;
    hlen = p - data;
    /* Now we know how much data we're expecting after the blank line. */
    if (evbuffer_get_length(source) < hlen + clen)
      return 0; /* incomplete */

    /* we are go */
    if (evbuffer_drain(source, hlen))
      return -1;

    if ((uint64_t)evbuffer_remove_buffer(source, dest, clen) != clen)
      return -1;

    log_debug("x_http: decoded %lu byte response",
              (unsigned long)(hlen + clen));

    if (evbuffer_get_length(source) > 0) {
      log_warn("x_http: protocol error: extra response data");
      return -1;
    }

    downcast_steg(s)->have_received = 1;
    conn_expect_close(conn);
    return 0;
  } else {
    /* We need a scratch buffer here because the contract is that if
       we hit a decode error we *don't* write anything to 'dest'. */
    struct evbuffer *scratch;
    struct evbuffer_ptr s2, s3;
    uint8_t *data, *p, *limit;
    uint8_t c, h, secondhalf;

    log_debug("x_http: %lu byte query stream available",
              (unsigned long)evbuffer_get_length(source));

    if (downcast_steg(s)->have_received) {
      log_warn("x_http: protocol error: multiple queries");
      return -1;
    }

    /* Search for the second and third invariant bits of the query headers
       we expect.  We completely ignore the contents of the Host header. */
    s2 = evbuffer_search(source, http_query_2,
                         sizeof http_query_2 - 1, NULL);
    if (s2.pos == -1) {
      log_debug("x_http: did not find second piece of HTTP query");
      return 0;
    }
    s3 = evbuffer_search(source, http_query_3,
                         sizeof http_query_3 - 1, &s2);
    if (s3.pos == -1) {
      log_debug("x_http: did not find third piece of HTTP query");
      return 0;
    }
    log_assert(s3.pos + sizeof http_query_3 - 1
                <= evbuffer_get_length(source));

    data = evbuffer_pullup(source, s2.pos);
    if (memcmp(data, "GET /", sizeof "GET /"-1)) {
      log_debug("x_http: unexpected HTTP verb: %.*s", 5, data);
      return -1;
    }

    p = data + sizeof "GET /"-1;
    limit = data + s2.pos;

    scratch = evbuffer_new();
    if (!scratch) return -1;
    if (evbuffer_expand(scratch, (limit - p)/2)) {
      evbuffer_free(scratch);
      return -1;
    }

    secondhalf = 0;
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
        log_debug("x_http: decode error: unexpected URI character %c", *p);
        return -1;
      }

      c = (c << 4) + h;
      if (secondhalf)
        evbuffer_add(scratch, &c, 1);
      secondhalf = !secondhalf;
      p++;
    }

    if (evbuffer_add_buffer(dest, scratch)) {
      evbuffer_free(scratch);
      log_debug("x_http: failed to transfer buffer");
      return -1;
    }
    evbuffer_drain(source, s3.pos + sizeof http_query_3 - 1);
    evbuffer_free(scratch);
    log_debug("x_http: decoded %lu byte query",
              (unsigned long)(s3.pos + sizeof http_query_3 - 1));

    if (evbuffer_get_length(source) > 0) {
      log_warn("x_http: protocol error: extra query data");
      return -1;
    }

    downcast_steg(s)->have_received = 1;
    conn_transmit_soon(conn, 2);
    return 0;
  }
}
