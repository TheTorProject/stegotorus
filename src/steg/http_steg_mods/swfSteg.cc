/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#include "util.h"
#include "../payload_server.h"
#include "swfSteg.h"
#include "compression.h"
#include "connections.h"

#include <event2/buffer.h>

static const char http_response_1[] =
  "HTTP/1.1 200 OK\r\n"
  "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
  "Cache-Control: no-store\r\n"
  "Connection: close\r\n"
  "Content-Type: application/x-shockwave-flash\r\n"
  "Content-Length: ";

unsigned int
swf_wrap(PayloadServer* pl, char* inbuf, int in_len, char* outbuf, int out_sz) {

  char* swf;
  int in_swf_len;

  char* tmp_buf;
  int out_swf_len;

  char* resp;
  int resp_len;

  char hdr[512];
  unsigned int hdr_len;

  char* tmp_buf2;
  


  if (!pl->get_payload(HTTP_CONTENT_SWF, -1, &resp, &resp_len)) {
    log_warn("swfsteg: no suitable payload found\n");
    return -1;
  }

  swf = strstr(resp, "\r\n\r\n") + 4;
  in_swf_len = resp_len - (swf - resp);



  
  if (out_sz - in_len < (SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 8 + 512)) {
    fprintf(stderr, "swfsteg: outbuf too small %d \n", out_sz - in_len);

    log_warn("swfsteg: outbuf too small\n");
    return -1;
  }


  tmp_buf = (char *)xmalloc(in_len + SWF_SAVE_HEADER_LEN + SWF_SAVE_FOOTER_LEN);
  tmp_buf2 = (char *)xmalloc(in_len + SWF_SAVE_HEADER_LEN + SWF_SAVE_FOOTER_LEN + 512);

  memcpy(tmp_buf, swf+8, SWF_SAVE_HEADER_LEN);
  memcpy(tmp_buf+SWF_SAVE_HEADER_LEN, inbuf, in_len);
  memcpy(tmp_buf+SWF_SAVE_HEADER_LEN+in_len, swf + in_swf_len - SWF_SAVE_FOOTER_LEN, SWF_SAVE_FOOTER_LEN);
  out_swf_len =
    compress((const uint8_t *)tmp_buf,
             SWF_SAVE_HEADER_LEN + in_len + SWF_SAVE_FOOTER_LEN,
             (uint8_t *)tmp_buf2+8,
             in_len + SWF_SAVE_HEADER_LEN + SWF_SAVE_FOOTER_LEN + 512-8,
             c_format_zlib);

  hdr_len =   gen_response_header((char*) "application/x-shockwave-flash", 0, out_swf_len + 8, hdr, sizeof(hdr));

  //  fprintf(stderr, "hdr = %s\n", hdr);
				       
  memcpy(tmp_buf2, swf, 4);
  ((int*) (tmp_buf2))[1] = out_swf_len;
  
  memcpy(outbuf, hdr, hdr_len);
  memcpy(outbuf+hdr_len, tmp_buf2, out_swf_len + 8);

  free(tmp_buf);
  free(tmp_buf2);
  return out_swf_len + 8 + hdr_len;
}




unsigned int
swf_unwrap(char* inbuf, int in_len, char* outbuf, int out_sz)
{
  int inf_len;
  size_t tmp_len = in_len * 32;
  char* tmp_buf = (char *)xmalloc(tmp_len);

  for (;;) {
    inf_len = decompress((const uint8_t *)inbuf + 8, in_len - 8,
                         (uint8_t *)tmp_buf, tmp_len);
    if (inf_len != -2)
      break;
    tmp_len *= 2;
    tmp_buf = (char *)xrealloc(tmp_buf, tmp_len);
  }

  if (inf_len < 0 ||
      out_sz < inf_len - SWF_SAVE_HEADER_LEN - SWF_SAVE_FOOTER_LEN) {
    fprintf(stderr, "inf_len = %d\n", inf_len);
    free(tmp_buf);
    return -1;
  }

  memcpy(outbuf, tmp_buf + SWF_SAVE_HEADER_LEN,
         inf_len - SWF_SAVE_HEADER_LEN - SWF_SAVE_FOOTER_LEN);
  return inf_len - SWF_SAVE_HEADER_LEN - SWF_SAVE_FOOTER_LEN;
}

int
http_server_SWF_transmit(PayloadServer* pl, struct evbuffer *source, conn_t *conn)
{

  struct evbuffer *dest = conn->outbound();
  size_t sbuflen = evbuffer_get_length(source);
  char* inbuf;
  char* outbuf;
  int outlen;

  inbuf = (char *)xmalloc(sbuflen);

  if (evbuffer_remove(source, inbuf, sbuflen) == -1) {
    log_debug("evbuffer_remove failed in http_server_SWF_transmit");
    return -1;
  }

  outbuf = (char *)xmalloc(4*sbuflen + SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 512);

  //  fprintf(stderr, "server wrapping swf len %d\n", (int) sbuflen);
  outlen = swf_wrap(pl, inbuf, sbuflen, outbuf, 4*sbuflen + SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 512);

  if (outlen < 0) {
    log_warn("swf_wrap failed\n");
    //    fprintf(stderr, "swf_wrap failed\n");
    free(inbuf);
    free(outbuf);
    return -1;
  }

  
  if (evbuffer_add(dest, outbuf, outlen)) {
    log_debug("SERVER ERROR: http_server_transmit: evbuffer_add() fails for jsTemplate");
    free(inbuf);
    free(outbuf);
    return -1;
  }

  free(inbuf);
  free(outbuf);
  return 0;
}




int
http_handle_client_SWF_receive(steg_t *, conn_t *conn, struct evbuffer *dest, struct evbuffer* source) {
  struct evbuffer_ptr s2;
  unsigned int response_len = 0, hdrLen;
  char outbuf[HTTP_MSG_BUF_SIZE];
  int content_len = 0, outbuflen;
  char *httpHdr, *httpBody;



  s2 = evbuffer_search(source, "\r\n\r\n", sizeof ("\r\n\r\n") -1 , NULL);
  if (s2.pos == -1) {
    log_warn("CLIENT Did not find end of HTTP header %d", (int) evbuffer_get_length(source));
    fprintf(stderr, "client did not find end of HTTP header\n");

    //    evbuffer_dump(source, stderr);
    return RECV_INCOMPLETE;
  }

  log_debug("CLIENT received response header with len %d", (int)s2.pos);

  response_len = 0;
  hdrLen = s2.pos + strlen("\r\n\r\n");
  response_len += hdrLen;

  httpHdr = (char *) evbuffer_pullup(source, s2.pos);
  if (httpHdr == NULL) {
    log_warn("CLIENT unable to pullup the complete HTTP header");
    return RECV_BAD;
  }

  content_len = find_content_length(httpHdr, hdrLen);



  if (content_len < 0) {
    log_warn("CLIENT unable to find content length");
    return RECV_BAD;
  }
  log_debug("CLIENT received Content-Length = %d\n", content_len);



  response_len += content_len;

  if (response_len > evbuffer_get_length(source))
    return RECV_INCOMPLETE;



  httpHdr = (char *) evbuffer_pullup(source, response_len);
  httpBody = httpHdr + hdrLen;


  outbuflen = swf_unwrap(httpBody, content_len, outbuf, HTTP_MSG_BUF_SIZE);

  if (outbuflen < 0) {
    fprintf(stderr, "swf_unwrap failed\n");
    log_debug("CLIENT ERROR: swf_unwrap failed\n");
    return RECV_BAD;
  }

  //  fprintf(stderr, "CLIENT unwrapped data of length %d:", outbuflen);
  // buf_dump(outbuf, outbuflen, stderr);

  if (evbuffer_add(dest, outbuf, outbuflen)) {
    log_debug("CLIENT ERROR: evbuffer_add to dest fails\n");
    return RECV_BAD;
  }

  // log_debug("Drained source for %d char\n", response_len);
  if (evbuffer_drain(source, response_len) == -1) {
    log_debug("CLIENT ERROR: failed to drain source\n");
    return RECV_BAD;
  }

  //  downcast_steg(s)->have_received = 1;
  conn->expect_close();
  return RECV_GOOD;
}
