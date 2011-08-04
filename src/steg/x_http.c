/* steganography example - somewhat pseudocode */

STEG_DECLARE_MODULE(basic_http,
                    1024,  /* client-server max data rate - made up */
                    10240, /* server-client max data rate - ditto */
                    1,     /* max concurrent connections per IP */
                    1);     /* max concurrent IPs */

struct basic_http_steg_state_t
{
  steg_state_t super;
  /* no extra stuff is presently necessary */
};

steg_state_t *
basic_http_new_clientside(rng_t *rng, ...)
{
  STEG_NEW_CLIENTSIDE(basic_http, state, rng);
  /* if there were extra stuff to fill in, you would do it here */
  return upcast_steg_state(state);
}

steg_state_t *
basic_http_new_serverside(rng_t *rng, ...)
{
  STEG_NEW_SERVERSIDE(basic_http, state, rng);
  /* if there were extra stuff to fill in, you would do it here */
  return upcast_steg_state(state);
}

void
basic_http_state_free(steg_state_t *s)
{
  basic_http_steg_state_t *state = downcast_steg_state(s);
  STEG_STATE_FREE(s);
  /* if there were extra stuff to deallocate, you would do it here */
  free(state);
}

/* Canned HTTP query and response headers.
   The "GET /" part of the query is added separately (see below). */
static const char http_query[] =
  " HTTP/1.1\r\n"
  "Host: %s\r\n"
  "Connection: close\r\n\r\n";

static const char http_response[] =
  "HTTP/1.1 200 OK\r\n"
  "Server: obfsproxy 0.0\r\n"
  "Date: %s GMT\r\n"
  "Cache-Control: max-age=0\r\n"
  "Connection: close\r\n"
  "Content-Length: %lu\r\n"
  "Content-Type: application/octet-stream\r\n\r\n";

static const char server_fp[] =
  "HTTP/1.1 200 OK\r\n"
  "Server: obfsproxy 0.0\r\n"
  "Date: ";

enum { yes, no, need_more_data }
basic_http_is_my_steg(conn_t *conn)
{
  struct evbuffer *buf = conn_get_inbound(conn);

  if (s->is_clientside) {
    /* Look for the first two lines of the above canned HTTP response. */
    if (evbuffer_get_length(buf) < sizeof server_fp - 1)
      return need_more_data;
    unsigned char *data = evbuffer_pullup(buf, sizeof server_fp - 1);

    return memcmp(data, server_fp, sizeof server_fp - 1) ? no : yes;

  } else {
    /* The client always transmits "GET /" followed by at least four
       characters that are either lowercase hex digits or equals
       signs, so we need nine bytes of incoming data. */
    if (evbuffer_get_length(buf) < 9)
      return need_more_data;

    unsigned char *data = evbuffer_pullup(buf, 9);
    if (memcmp(data, "GET /", 5))
      return no;

    for (unsigned char *p = data+5; p < data+9; p++)
      if (!isxdigit(p) && p != '=')
        return no;

    return yes;
  }
}

size_t
basic_http_transmit_room(steg_state_t *s, conn_t *conn)
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

enum { success, encode_error }
basic_http_transmit(steg_state_t *s, struct evbuffer *source, conn_t *conn)
{
  struct evbuffer *dest = conn_get_outbound(conn);

  if (s->is_clientside) {
    /* On the client side, we have to embed the data in a GET query somehow;
       the only plausible places to put it are the URL and cookies.  This
       presently uses the URL. And it can't be binary. */
    struct evbuffer *scratch = evbuffer_new();
    const char *peername = conn_get_peername(conn);

    /* Convert all the data in 'source' to hexadecimal and write it to
       'scratch'. Data is padded to a multiple of four characters with
       equals signs. */
    size_t slen = evbuffer_get_length(source);
    size_t dlen = slen * 2;
    size_t dput = 0;

    dlen = dlen + 3 - (dlen-1)%4;
    if (dlen == 0) dlen = 4;

    if (evbuffer_expand(scratch, dlen)) return encode_error;

    while (evbuffer_get_length(source) > 0) {
      size_t chunk = evbuffer_get_contiguous_space(source);
      unsigned char *data = evbuffer_pullup(source, chunk);
      char hex[2], c;
      for (size_t i = 0; i < chunk; i++) {
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

    if (evbuffer_add(dest, "GET /", sizeof "GET /"-1)) return encode_error;
    if (evbuffer_add_buffer(dest, scratch)) return encode_error;
    if (evbuffer_add_printf(dest, http_query, peername)) return encode_error;

    evbuffer_free(scratch);
    conn_expect_close_after_response(conn);
    return success;

  } else {
    /* On the server side, we just fake up some HTTP response headers and
       then splat the data we were given. Binary is OK. */
    char *date = asctime(gmtime(time(0)));
    date[strlen(date)-1] = '\0'; /* chop off the newline */

    if (evbuffer_add_printf(dest, http_response, date,
                            (unsigned long)evbuffer_get_length(source)))
      return encode_error;
    if (evbuffer_add_buffer(dest, source))
      return encode_error;

    conn_close_after_transmit(conn);
    return success;
  }
}

enum { success, decode_error, need_more_data }
basic_http_receive(steg_state_t *s, conn_t *conn, struct evbuffer *dest)
{
  struct evbuffer *source = conn_get_inbound(conn);
  if (s->is_clientside) {
    const size_t minheader =
        (sizeof http_response - 1)
      - (sizeof "%s%lu" - 1)
      + (sizeof "Dow Mmm Dd Hh:Mm:Ss Yyyy" - 1)
      + 1 /* minimum length of Content-Length: */;

    /* Validate response headers. */
    if (evbuffer_get_length(source) < minheader)
      return need_more_data;

    unsigned char *data = evbuffer_pullup(buf, minheader);
    if (memcmp(data, server_fp, sizeof server_fp - 1))
      return decode_error;

    /* Scan for Content-Length. */
    struct evbuffer_ptr lenptr =
      evbuffer_search(source, "\r\nContent-Length: ",
                      sizeof "\r\nContent-Length: " - 1,
                      NULL);
    if (evbuffer_ptr_set(source, lenptr, sizeof "\r\nContent-Length: " - 1,
                         EVBUFFER_PTR_ADD))
      return decode_error;

    /* Note: we cannot use evbuffer_readln here, as it drains and cannot
       be given an offset. */

    struct evbuffer_ptr lenend =
      evbuffer_search_eol(source, &lenptr, NULL, EVBUFFER_EOL_CRLF_STRICT);

    /* XXX this won't work correctly if there's a buffer boundary between
       'lenptr' and 'lenend'. Pulling up 'minheader' bytes, above, should
       have made this impossible, but. */
    struct evbuffer_iovec v;
    if (evbuffer_peek(source, lenend.pos - lenptr.pos, lenptr, &v, 1) != 1)
      return decode_error;

    /* XXX ignores available data length */
    char *endptr;
    unsigned long content_length = strtoul(v.iov_base, &endptr, 10);
    if (endptr == v.iov_base || (*endptr != '\r' && *endptr != '\n'))
      return decode_error;

    /* Now we know how much data we're expecting after the blank line. */
    struct evbuffer_ptr eoh = evbuffer_search(source, "\r\n\r\n", 4, &lenend);
    if (eoh.pos == -1)
      return need_more_data;
    if (evbuffer_get_length(source) < eoh.pos + 4 + content_length)
      return need_more_data;

    /* we are go */
    if (evbuffer_drain(source, eoh.pos + 4))
      return decode_error;

    if (evbuffer_remove_buffer(source, dest, content_length) != content_length)
      return decode_error;

    conn_expect_close(conn);
    return success;
  } else {
    /* left as an exercise */
  }
}
