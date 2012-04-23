#include "util.h"
#include "pdfSteg.h"
#include "connections.h"
#include "payloads.h"
#include <event2/buffer.h>

/* pdfSteg: A PDF-based steganography module */

#define PDF_DELIMITER    '?'
#define PDF_DELIMITER2   '.'

#define STREAM_BEGIN       ">>stream"
#define STREAM_BEGIN_SIZE  8
#define STREAM_END         "endstream"
#define STREAM_END_SIZE    9

#define DEBUG

/*
 * pdf_add_delimiter processes the input buffer (inbuf) of length
 * inbuflen, copies it to output buffer (outbuf) of size outbufsize,
 * and adds a two-char-long, end-of-data pattern at the end of outbuf
 * based on delimiter1 and delimiter2.
 *
 * The end-of-data pattern consists of delimiter1 followed by a char
 * that is not delimiter1. Thus, delimiter1 and delimiter2 must be
 * different.
 *
 * If delimiter1 appears in the input buffer, pdf_add_delimiter puts two
 * delimiter1 characters in the output buffer, so that the transformation
 * is reversible.
 *
 * pdf_add_delimiter returns the length of the data written to outbuf,
 * including the end-of-data pattern, if the transformation succeeds;
 * otherwise, it returns -1.
 *
 */
ssize_t
pdf_add_delimiter(const char *inbuf, size_t inbuflen,
                  char *outbuf, size_t outbuflen,
                  const char delimiter1, const char delimiter2)
{
  size_t cnt;
  const char *ibp;
  char ic, rc;

  log_assert(delimiter1 != delimiter2);
  if (inbuflen > SIZE_T_CEILING || outbuflen > SIZE_T_CEILING)
    return -1;

  cnt = 0;
  ibp = inbuf;
  while (size_t(ibp-inbuf) < inbuflen && cnt < outbuflen-2) {
    ic = *ibp++;
    if (ic != delimiter1) {
      outbuf[cnt++] = ic;
    } else {
      outbuf[cnt++] = delimiter1;
      outbuf[cnt++] = delimiter1;
    }
  }

  // error if outbuf is not large enough for storing the resulting data
  if (cnt >= outbuflen-2)
    return -1;

  // put delimiter1 and a char that is not a delimiter1
  // as the end-of-data pattern at the end of outbuf
  outbuf[cnt++] = delimiter1;
  // try to get a random char (that is not delimiter1)
  rc = (char) (rand() % 256);
  if (rc != delimiter1) {
    outbuf[cnt++] = rc;
  } else { // unable to get a rand char != delimiter1, use delimiter2
    outbuf[cnt++] = delimiter2;
  }
  return cnt;
}


/*
 * pdf_remove_delimiter performs the reverse transformation of
 * pdf_add_delimiter.
 *
 * returns the length of data written to outbuf, if succeed;
 * otherwise, it returns -1
 *
 * endFlag indicates whether the end-of-encoding byte pattern (i.e.,
 * delimiter1 followed by non-delimiter1) is detected
 *
 * escape indicates if a dangling delimiter1 has been
 * seen in the previous invocation of pdf_remove_delimiter
 */
ssize_t
pdf_remove_delimiter(const char *inbuf, size_t inbuflen,
                     char *outbuf, size_t outbuflen,
                     char delimiter1, bool *endFlag, bool *escape)
{
  size_t cnt;
  const char *ibp;
  char ic1, ic2;

  cnt = 0;
  *endFlag = false;
  ibp = inbuf;

  if (inbuflen > SIZE_T_CEILING || outbuflen > SIZE_T_CEILING)
    return -1;

  // special case: 2-char, end-of-data pattern could be in two buffers
  // if *escape == true, we need to see if
  // 1) (*ibp == delimiter1) -> put delimiter1 in outbuf
  // 2) (*ibp != delimiter1) -> end-of-data detected
  if (*escape) {
    ic1 = *ibp;
    if (ic1 == delimiter1) {
      outbuf[cnt++] = ic1; ibp++;
    } else {
      *endFlag = 1;
      return 0;
    }
  }

  *escape = false;
  while (size_t(ibp-inbuf+1) < inbuflen && cnt < outbuflen) {
    ic1 = *ibp++;
    if (ic1 != delimiter1) {
      outbuf[cnt++] = ic1;
    } else {
      // lookahead 1 char
      ic2 = *ibp;
      // if the next char is delimiter1
      if (ic2 == delimiter1) {
        outbuf[cnt++] = delimiter1; ibp++;
      } else { // end-of-data pattern detected
        *endFlag = true;
        return cnt;
      }
    }
  }

  if (size_t(ibp-inbuf) == inbuflen)
    return cnt;

  // handling the last char in inbuf, if needed
  ic1 = *ibp;
  if (ic1 != delimiter1) {
    outbuf[cnt++] = ic1;
  } else {
    // look at the next stream obj to handle the special cases
    *escape = true;
  }

  return cnt;
}

/*
 * pdf_wrap embeds data of length dlen inside the stream objects of the PDF
 * document (length plen) that appears in the body of a HTTP msg, and
 * stores the result in the output buffer of size outsize
 *
 * pdf_wrap returns the length of the pdf document with the data embedded
 * inside, if succeed; otherwise, it returns -1 to indicate an error
 *
 */
ssize_t
pdf_wrap(const char *data, size_t dlen,
         const char *pdfTemplate, size_t plen,
         char *outbuf, size_t outbufsize)
{
  char data2[dlen*2+2];
  const char *tp, *dp, *plimit;
  char *op, *streamStart, *streamEnd;
  size_t data2len, cnt, size, size2;
  ssize_t rv;

  if (dlen > SIZE_T_CEILING || plen > SIZE_T_CEILING ||
      outbufsize > SIZE_T_CEILING)
    return -1;

  // assumption: pdf_wrap is length-preserving
  if (outbufsize < plen) return -1;

  rv = pdf_add_delimiter(data, dlen, data2, HTTP_MSG_BUF_SIZE,
                               PDF_DELIMITER, PDF_DELIMITER2);
  if (rv < 1)
    return -1;
  data2len = rv;

  op = outbuf;       // current pointer for output buffer
  tp = pdfTemplate;  // current pointer for http msg template
  dp = data2;        // current pointer for data2
  cnt = 0;           // number of data char encoded
  plimit = pdfTemplate+plen;

  while (tp < plimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, tp, plimit-tp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    // copy everything between tp and "stream" (inclusive) to outbuf
    size = streamStart - tp + STREAM_BEGIN_SIZE;
    memcpy(op, tp, size);
    op += size;
    tp = streamStart + STREAM_BEGIN_SIZE;

    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, tp, plimit-tp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    // count the number of usable char between tp and streamEnd
    size = streamEnd-tp;

    // encoding data in the stream obj
    if (size > 0) {
        size2 = data2len - cnt;
        if (size < size2) {
          memcpy(op, dp, size);
          op += size; tp += size; dp += size;
          memcpy(op, tp, STREAM_END_SIZE);
          op += STREAM_END_SIZE; tp += STREAM_END_SIZE;
          cnt += size;
        } else { // done encoding data
          memcpy(op, dp, size2);
          op += size2; tp += size2; dp += size2;
          cnt += size2;
          break;
        }
        log_debug("Encoded %lu bytes in pdf", (unsigned long)size);
    } else { // empty stream
      memcpy(op, tp, STREAM_END_SIZE);
      op += STREAM_END_SIZE; tp += STREAM_END_SIZE;
    }

    if (cnt >= data2len) break; // this shouldn't happen ...
  }

  // copy the rest of pdfTemplate to outbuf
  size = plimit-tp;
  log_debug("copying the rest of pdfTemplate to outbuf (size %lu)",
            (unsigned long)size);
  memcpy(op, tp, size);
  op += size;
  return (op-outbuf);
}

/*
 * pdf_unwrap is the inverse operation of pdf_wrap
 */
ssize_t
pdf_unwrap(const char *data, size_t dlen,
           char *outbuf, size_t outbufsize)
{
  const char *dp, *dlimit;
  char *op, *streamStart, *streamEnd, *olimit;
  size_t cnt, size, size2;
  bool endFlag, escape = false;

  if (dlen > SIZE_T_CEILING || outbufsize > SIZE_T_CEILING)
    return -1;

  dp = data;   // current pointer for data
  op = outbuf; // current pointer for outbuf
  cnt = 0;     // number of char decoded
  dlimit = data+dlen;
  olimit = outbuf+outbufsize;

  while (dp < dlimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, dp, dlimit-dp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    dp = streamStart + STREAM_BEGIN_SIZE;
    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, dp, dlimit-dp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    // count the number of usable char between tp and streamEnd
    size = streamEnd-dp;

    if (size > 0) {
      ssize_t rv = pdf_remove_delimiter(dp, size, op, olimit-op, PDF_DELIMITER,
                                        &endFlag, &escape);
      if (rv < 0)
        return -1;

      size2 = rv;
      cnt += size2;
      if (endFlag) { // Done decoding
        break;
      } else { // Continue decoding
        op += size2;
        dp = streamEnd + STREAM_END_SIZE;
      }
    } else { // empty stream obj
      dp = streamEnd + STREAM_END_SIZE;
    }
  }

  return cnt;
}

int
http_server_PDF_transmit(payloads &pl, struct evbuffer *source,
                         conn_t *conn)
{
  struct evbuffer *dest = conn->outbound();
  size_t sbuflen = evbuffer_get_length(source);
  unsigned int mpdf;
  char *pdfTemplate = NULL, *hend;
  int pdfTemplateSize = 0;
  char data1[sbuflen];
  char outbuf[HTTP_MSG_BUF_SIZE];
  int cnt, hLen, outbuflen, i;

  char newHdr[MAX_RESP_HDR_SIZE];
  int newHdrLen = 0;

  struct evbuffer_iovec *iv;
  int nv;

  log_debug("Entering SERVER PDF transmit with sbuflen %d", (int)sbuflen);

  nv = evbuffer_peek(source, sbuflen, NULL, NULL, 0);
  iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);

  if (evbuffer_peek(source, sbuflen, NULL, iv, nv) != nv) {
    free(iv);
    return -1;
  }

  cnt = 0;
  for (i = 0; i < nv; i++) {
    const unsigned char *p = (const unsigned char *)iv[i].iov_base;
    const unsigned char *limit = p + iv[i].iov_len;
    while (p < limit && cnt < (int)sbuflen) {
      data1[cnt++] = *p++;
    }
  }

  free(iv);

  log_debug("SERVER sbuflen = %d; cnt = %d", (int)sbuflen, cnt);

  mpdf = pl.max_PDF_capacity;

  if (mpdf <= 0) {
    log_warn("SERVER ERROR: No pdfTemplate found\n");
    return -1;
  }

  if (sbuflen > (size_t) mpdf) {
    log_warn("SERVER ERROR: pdfTemplate cannot accommodate data %d %dn",
                (int) sbuflen, (int) mpdf);
    return -1;
  }

  if (get_payload(pl, HTTP_CONTENT_PDF, sbuflen, &pdfTemplate,
                  &pdfTemplateSize) == 1) {
    log_debug("SERVER found the next HTTP response template with size %d",
              pdfTemplateSize);
  } else {
    log_warn("SERVER couldn't find the next HTTP response template");
    return -1;
  }

  hend = strstr(pdfTemplate, "\r\n\r\n");
  if (hend == NULL) {
    log_warn("SERVER unable to find end of header in the HTTP template");
    return -1;
  }

  hLen = hend+4-pdfTemplate;

  log_debug("SERVER calling pdf_wrap for data1 with length %d", cnt);
  outbuflen = pdf_wrap(data1, cnt, hend+4, pdfTemplateSize-hLen, outbuf,
                      HTTP_MSG_BUF_SIZE);
  if (outbuflen < 0) {
    log_warn("SERVER pdf_wrap fails");
    return -1;
  }
  log_debug("SERVER pdfSteg sends resp with hdr len %d body len %d",
            hLen, outbuflen);

  newHdrLen = gen_response_header((char*) "application/pdf", 0,
                                  outbuflen, newHdr, sizeof(newHdr));
  if (newHdrLen < 0) {
    log_warn("SERVER ERROR: gen_response_header fails for pdfSteg");
    return -1;
  }

  if (evbuffer_add(dest, newHdr, newHdrLen)) {
    log_warn("SERVER ERROR: evbuffer_add() fails for newHdr");
    return -1;
  }

  if (evbuffer_add(dest, outbuf, outbuflen)) {
    log_warn("SERVER ERROR: evbuffer_add() fails for outbuf");
    return -1;
  }

  evbuffer_drain(source, sbuflen);

  conn->cease_transmission();
  return 0;
}

int
http_handle_client_PDF_receive(steg_t *, conn_t *conn, struct evbuffer *dest,
                               struct evbuffer* source)
{
  struct evbuffer_ptr s2;
  unsigned int response_len = 0, hdrLen;
  char outbuf[HTTP_MSG_BUF_SIZE];
  int content_len = 0, outbuflen;
  char *httpHdr, *httpBody;

  log_debug("Entering CLIENT PDF receive");

  s2 = evbuffer_search(source, "\r\n\r\n", sizeof ("\r\n\r\n") -1 , NULL);
  if (s2.pos == -1) {
    log_warn("CLIENT Did not find end of HTTP header %d",
             (int) evbuffer_get_length(source));
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

  if (httpHdr == NULL) {
    log_warn("CLIENT unable to pullup the complete HTTP body");
    return RECV_BAD;
  }

  httpBody = httpHdr + hdrLen;

  outbuflen = pdf_unwrap(httpBody, content_len, outbuf, HTTP_MSG_BUF_SIZE);
  if (outbuflen < 0) {
    log_warn("CLIENT ERROR: pdf_unwrap fails\n");
    return RECV_BAD;
  }

  log_debug("CLIENT unwrapped data of length %d:", outbuflen);

  if (evbuffer_add(dest, outbuf, outbuflen)) {
    log_warn("CLIENT ERROR: evbuffer_add to dest fails\n");
    return RECV_BAD;
  }

  if (evbuffer_drain(source, response_len) == -1) {
    log_warn("CLIENT ERROR: failed to drain source\n");
    return RECV_BAD;
  }

  conn->expect_close();
  return RECV_GOOD;
}
