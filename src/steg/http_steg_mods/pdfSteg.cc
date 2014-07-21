/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h" //this need to be included early cause : "C++ implementations should define these macros only when __STDC_LIMIT_MACROS is defined before is included"
// From: http://stackoverflow.com/a/3233069/1039165
#include <event2/buffer.h>


#include "connections.h"
#include "compression.h"

#include "payload_server.h"
#include "pdfSteg.h"

/* pdfSteg: A PDF-based steganography module */

#define PDF_DELIMITER    '?'
#define PDF_DELIMITER2   '.'

#define STREAM_BEGIN       "stream"
#define STREAM_BEGIN_SIZE  6
#define STREAM_END         "endstream"
#define STREAM_END_SIZE    9

#define DEBUG


ssize_t PDFSteg::headless_capacity(char *cover_body, int body_length)
{
  return static_headless_capacity((char*)cover_body, body_length);
}


ssize_t PDFSteg::capacity(const uint8_t *cover_payload, size_t len)
{
  return static_capacity((char*)cover_payload, len);
}

unsigned int PDFSteg::static_capacity(char *cover_body, int body_length)
{
	return static_headless_capacity((char *)cover_body, body_length);
}


unsigned int PDFSteg::static_headless_capacity(char *cover_body, int body_length)
{
  
 
  if (body_length <= 0)
     return 0;
  
  //we don't care about body_length, the capacity is always at max
  (void)cover_body; //to get around warning
  (void)body_length;

  //the http response header also need to be fit in the outbuf
  ssize_t hypothetical_capacity = c_HTTP_MSG_BUF_SIZE;

  return max(hypothetical_capacity, (ssize_t)0);

}
unsigned int
PDFSteg::capacity (const uint8_t* buffer, size_t len) {
  char *hEnd, *bp, *streamStart, *streamEnd;
  int cnt=0;
  int size;

  // jump to the beginning of the body of the HTTP message
  hEnd = strstr((char *)buffer, "\r\n\r\n");
  if (hEnd == NULL) {
    // cannot find the separator between HTTP header and HTTP body
    return 0;
  }
  bp = hEnd + 4;

  while (bp < (buf+len)) {
     streamStart = strInBinary("stream", 6, bp, (buf+len)-bp);
     if (streamStart == NULL) break;
     bp = streamStart+6;
     streamEnd = strInBinary("endstream", 9, bp, (buf+len)-bp);
     if (streamEnd == NULL) break;
     // count the number of char between streamStart+6 and streamEnd
     size = streamEnd - (streamStart+6) - 2; // 2 for \r\n before streamEnd
     if (size > 0) {
       cnt = cnt + size;
       // log_debug("capacity of pdf increase by %d", size);
     }
     bp += 9;
  }
  return cnt;
}

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
 * strInBinaryRewind looks for char array pattern of length patternLen
 * in a char array blob of length blobLen in the *reverse* direction
 *
 * return a pointer for the first occurrence of pattern in blob,
 * starting from the end of blob, if found; otherwise, return NULL
 *
 */
//change this to uint8_t * return in future?
char *
strInBinaryRewind (const char *pattern, unsigned int patternLen,
             const char *blob, unsigned int blobLen) {
  int found = 0;
  char *cp;

  if (patternLen < 1 || blobLen < 1) return 0;
  cp = (char *) blob + blobLen - 1;
  while (cp >= blob) {
    if (cp - (patternLen-1) < blob) break;
    if (*cp == pattern[patternLen-1]) {
      if (memcmp(cp-(patternLen-1), pattern, patternLen-1) == 0) {
        found = 1;
        break;
      }
    }
    cp--;
  }
  if (found) return (cp-(patternLen-1));
  else return NULL;
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
/*ssize_t
pdf_wrap(const char *data, size_t dlen,
         const char *pdfTemplate, size_t plen,
         char *outbuf, size_t outbufsize) //outbufsize is fixed, what to do about plen, pdftemplate, pdftemplate is payloadbuf?
{
  int data2size = 2*dlen+10; 
  // see rfc 1950 for zlib format, in addition to compressed data, we have
  // 2-byte compression method and flags +
  // 4-byte dict ID +
  // 4-byte ADLER32 checksum
  char data2[data2size];
  const char *tp, *plimit;
  char *op, *streamStart, *streamEnd, *filterStart;
  size_t data2len, size;
  int np;

  if (dlen > SIZE_T_CEILING || plen > SIZE_T_CEILING ||
      outbufsize > SIZE_T_CEILING)
    return -1;

  data2len = compress((const uint8_t *)data, dlen, 
                      (uint8_t *)data2, data2size, c_format_zlib);
  if ((int)data2len < 0) {
    log_warn("compress failed and returned %lu", (unsigned long)data2len);
    return -1;
  }

  op = outbuf;       // current pointer for output buffer
  tp = pdfTemplate;  // current pointer for http msg template
  plimit = pdfTemplate+plen;

  while (tp < plimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, tp, plimit-tp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, tp, plimit-tp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    filterStart = strInBinaryRewind(" obj", 4, tp, streamStart-tp);
    if (filterStart == NULL) {
      log_warn("Cannot find obj\n");
      return -1;
    } else {
      // copy everything between tp and up and and including "obj" to outbuf
      size = filterStart - tp + 4;
      memcpy(op, tp, size);
      op[size] = 0;
      op += size;

      // write meta-data for stream object
      np = sprintf(op, " <<\n/Length %d\n/Filter /FlateDecode\n>>\nstream\n", (int)data2len);
      if (np < 0) {
        log_warn("sprintf failed\n");
        return -1;
      }
      op += np;

      // copy compressed data to outbuf 
      memcpy(op, data2, data2len);
      op += data2len;

      // write endstream to outbuf
      np = sprintf(op, "\nendstream");
      if (np < 0) {
        log_warn("sprintf failed\n");
        return -1;
      }
      op += np;
    }

    // done with encoding data
    tp = streamEnd+STREAM_END_SIZE;
    break;
  }

  // copy the rest of pdfTemplate to outbuf
  size = plimit-tp;
  log_debug("copying the rest of pdfTemplate to outbuf (size %lu)",
            (unsigned long)size);
  memcpy(op, tp, size);
  op += size;
  return (op-outbuf);
}*/

int PDFSteg::encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len)
{
  size_t data2size = 2*cover_len+10; 
  // see rfc 1950 for zlib format, in addition to compressed data, we have
  // 2-byte compression method and flags +
  // 4-byte dict ID +
  // 4-byte ADLER32 checksum
   uint8_t * data2[data2size];
  const uint8_t  *tp, *plimit;
  char *op, *streamStart, *streamEnd, *filterStart;
  size_t data2len, size;
  int np;

  if (cover_len > SIZE_T_CEILING || data_len > SIZE_T_CEILING ||
      HTTP_MSG_BUF_SIZE > SIZE_T_CEILING) //remove last condition?
    return -1;

  data2len = compress((const uint8_t *)data, cover_len, 
                     data2, data2size, c_format_zlib);
  if ((int)data2len < 0) {
    log_warn("compress failed and returned %lu", (unsigned long)data2len);
    return -1;
  }

  op = data;       // current pointer for output buffer
  tp = cover_payload  // current pointer for http msg template, replace with payloadbuf?
  plimit = cover_payload+cover_len;

  while (tp < plimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, tp, plimit-tp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, tp, plimit-tp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    filterStart = strInBinaryRewind(" obj", 4, tp, streamStart-tp);
    if (filterStart == NULL) {
      log_warn("Cannot find obj\n");
      return -1;
    } else {
      // copy everything between tp and up and and including "obj" to outbuf
      size = filterStart - tp + 4;
      memcpy(op, tp, size);
      op[size] = 0;
      op += size;

      // write meta-data for stream object
      np = sprintf(op, " <<\n/Length %d\n/Filter /FlateDecode\n>>\nstream\n", (int)data2len);
      if (np < 0) {
        log_warn("sprintf failed\n");
        return -1;
      }
      op += np;

      // copy compressed data to outbuf 
      memcpy(op, data2, data2len);
      op += data2len;

      // write endstream to outbuf
      np = sprintf(op, "\nendstream");
      if (np < 0) {
        log_warn("sprintf failed\n");
        return -1;
      }
      op += np;
    }

    // done with encoding data
    tp = streamEnd+STREAM_END_SIZE;
    break;
  }

  // copy the rest of pdfTemplate to outbuf
  size = plimit-tp;
  log_debug("copying the rest of pdfTemplate to outbuf (size %lu)",
            (unsigned long)size);
  memcpy(op, tp, size);
  op += size;
  return (op-data);
}

/*
 * pdf_unwrap is the inverse operation of pdf_wrap
 */
/*ssize_t
pdf_unwrap(const char *data, size_t dlen,
           char *outbuf, size_t outbufsize)
{
  const char *dp, *dlimit;
  char *op, *streamStart, *streamEnd;
  size_t cnt, size, size2;

  int streamObjStartSkip=0;
  int streamObjEndSkip=0;

  if (dlen > SIZE_T_CEILING || outbufsize > SIZE_T_CEILING)
    return -1;

  dp = data;   // current pointer for data
  op = outbuf; // current pointer for outbuf
  cnt = 0;     // number of char decoded
  dlimit = data+dlen;

   
  while (dp < dlimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, dp, dlimit-dp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    dp = streamStart + STREAM_BEGIN_SIZE;

    // streamObjStartSkip = size of end-of-line (EOL) char(s) after ">>stream"
    if ( *dp == '\r' && *(dp+1) == '\n' ) { // Windows-style EOL
      streamObjStartSkip = 2;
    } else if ( *dp == '\n' ) { // Unix-style EOL
      streamObjStartSkip = 1;
    }

    dp = dp + streamObjStartSkip;

    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, dp, dlimit-dp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    // streamObjEndSkip = size of end-of-line (EOL) char(s) at the end of stream obj
    if (*(streamEnd-2) == '\r' && *(streamEnd-1) == '\n') {
      streamObjEndSkip = 2;
    } else if (*(streamEnd-1) == '\n') {
      streamObjEndSkip = 1;
    }

    // compute the size of stream obj payload
    size = (streamEnd-streamObjEndSkip) - dp;

    size2 = decompress((const uint8_t *)dp, size, (uint8_t *)op, outbufsize);
    if ((int)size2 < 0) {
      log_warn("decompress failed; size2 = %d\n", (int)size2);
      return -1;
    } else {
      op += size2;
      cnt = size2;
      break;  // done decoding
    }
  }

  return cnt;
}*/

ssize_t
PDFSteg::decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data) //const char *data, size_t dlen,
           char *outbuf, size_t outbufsize
{
  const uint8_t *dp, *dlimit;
  uint8_t *op;
  char *streamStart, *streamEnd;
  size_t cnt, size, size2;
  size_t outbufsize = HTTP_MSG_BUF_SIZE;

  int streamObjStartSkip=0;
  int streamObjEndSkip=0;

  if (cover_len > SIZE_T_CEILING || outbufsize > SIZE_T_CEILING)
    return -1;

  dp = cover_payload;   // current pointer for data
  op = data; // current pointer for outbuf
  cnt = 0;     // number of char decoded
  dlimit = dp+cover_len;

   
  while (dp < dlimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, dp, dlimit-dp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    dp = streamStart + STREAM_BEGIN_SIZE;

    // streamObjStartSkip = size of end-of-line (EOL) char(s) after ">>stream"
    if ( *dp == '\r' && *(dp+1) == '\n' ) { // Windows-style EOL
      streamObjStartSkip = 2;
    } else if ( *dp == '\n' ) { // Unix-style EOL
      streamObjStartSkip = 1;
    }

    dp = dp + streamObjStartSkip;

    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, dp, dlimit-dp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    // streamObjEndSkip = size of end-of-line (EOL) char(s) at the end of stream obj
    if (*(streamEnd-2) == '\r' && *(streamEnd-1) == '\n') {
      streamObjEndSkip = 2;
    } else if (*(streamEnd-1) == '\n') {
      streamObjEndSkip = 1;
    }

    // compute the size of stream obj payload
    size = ((uint8_t *)streamEnd-streamObjEndSkip) - dp;

    size2 = decompress(dp, size, op, outbufsize);
    if ((int)size2 < 0) {
      log_warn("decompress failed; size2 = %d\n", (int)size2);
      return -1;
    } else {
      op += size2;
      cnt = size2;
      break;  // done decoding
    }
  }

  return (ssize_t) cnt;
}

int
http_server_PDF_transmit(PayloadServer* pl, struct evbuffer *source, conn_t *conn)
{
  struct evbuffer *dest = conn->outbound();
  size_t sbuflen = evbuffer_get_length(source);
  unsigned int mpdf; //not needed
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
//put above in encode? But no access to evbuffer? Use evbuffer_to_memory_block?

  /*log_debug("SERVER sbuflen = %d; cnt = %d", (int)sbuflen, cnt);
//move into ssize_t FileStegMod::pick_appropriate_cover_payload(size_t data_len, char** payload_buf, string& cover_id_hash)
  //TODO: this need to be investigated, we might need two functions
  mpdf = pl->_payload_database.typed_maximum_capacity(HTTP_CONTENT_PDF); //doesn't this default to PDF_MIN_AVAIL_SIZE?

  if (mpdf <= 0) {
    log_warn("SERVER ERROR: No pdfTemplate found\n");
    return -1;
  }

  if (sbuflen > (size_t) mpdf) {
    log_warn("SERVER ERROR: pdfTemplate cannot accommodate data %d %dn",
                (int) sbuflen, (int) mpdf);
    return -1;
  }
//pdfTemplate should probably be added in PDFSteg constructor as member variable (protected)? == payload_buf, add cover_id_hash
  if (pl->get_payload(HTTP_CONTENT_PDF, sbuflen, &pdfTemplate,
                  &pdfTemplateSize) == 1) {
    log_debug("SERVER found the next HTTP response template with size %d",
              pdfTemplateSize);
  } else {
    log_warn("SERVER couldn't find the next HTTP response template");
    return -1;
  }*/
 //ssize_t 
//FileStegMod::extract_appropriate_respones_body(char* payload_buf, size_t payload_size)
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

  //make sure this takes an ssize_t outbuflen!
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

PDFSteg::PDFSteg(PayloadServer* payload_provider, double noise2signal)
 :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_PDF)

{

}
