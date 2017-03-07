/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h" //this need to be included early cause : "C++ implementations should define these macros only when __STDC_LIMIT_MACROS is defined before is included"
// From: http://stackoverflow.com/a/3233069/1039165

#include <event2/buffer.h>
#include <assert.h>

#include "../payload_server.h"
#include "file_steg.h"
#include "pdfSteg.h"
#include "compression.h"
#include "connections.h"

/* pdfSteg: A PDF-based steganography module */

#define PDF_CONTENT_TYPE "application/pdf"
//#define PDF_SIZE_CEILING 20480

#define PDF_DELIMITER    '?'
#define PDF_DELIMITER2   '.'

#define STREAM_BEGIN       "stream"
#define STREAM_BEGIN_SIZE  6
#define STREAM_END         "endstream"
#define STREAM_END_SIZE    9

#define DEBUG


ssize_t PDFSteg::headless_capacity(char *cover_body, int body_length)
{
  return static_headless_capacity(cover_body,(size_t) body_length);
}


ssize_t PDFSteg::capacity(const uint8_t *cover_payload, size_t len)
{
  return static_capacity((char *) cover_payload, (int) len);
}

unsigned int PDFSteg::static_capacity(char *cover_payload, int body_length)
{
	  ssize_t body_offset = extract_appropriate_respones_body(cover_payload, body_length);
  if (body_offset == -1) {
    return 0; //useless payload
}
 
   return static_headless_capacity(cover_payload + body_offset, (size_t) (body_length - body_offset));
}


/*unsigned int PDFSteg::static_headless_capacity(char *cover_body, int body_length)
{
  
 
  if (body_length <= 0)
     return 0;
  
  //we don't care about body_length, the capacity is always at max
  (void)cover_body; //to get around warning
  (void)body_length;

  //the http response header also need to be fit in the outbuf
  ssize_t hypothetical_capacity = PDF_MAX_AVAIL_SIZE; //could be too small?

  return max(hypothetical_capacity, (ssize_t)0);

}*/
unsigned int
PDFSteg::static_headless_capacity (char* buf, size_t len) {
  char *bp, *streamStart, *streamEnd;
  int cnt=0;
  int size;

  // jump to the beginning of the body of the HTTP message
  /*hEnd = strstr((char *)buf, "\r\n\r\n");
  if (hEnd == NULL) {
    // cannot find the separator between HTTP header and HTTP body
    return 0;
  }*/
  bp = buf;

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
       //log_debug("capacity of pdf increase by %d", size);
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




int PDFSteg::encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len)
{
  size_t data2size = 2*cover_len+10; 
  // see rfc 1950 for zlib format, in addition to compressed data, we have
  // 2-byte compression method and flags +
  // 4-byte dict ID +
  // 4-byte ADLER32 checksum
   uint8_t data2[data2size];
  const char *tp, *plimit;
  char *op;
  char *streamStart, *streamEnd, *filterStart;
  size_t data2len, size;
  int np;

  assert(c_MAX_MSG_BUF_SIZE < SIZE_T_CEILING); //zlib offsetting limit
  if (cover_len > SIZE_T_CEILING || data_len > SIZE_T_CEILING) 
    return -1;

   if (headless_capacity((char*)cover_payload, cover_len) <  (int) data_len) {
    log_warn("not enough cover capacity to embed data");
    return -1; //not enough capacity is an error because you should have check     //before requesting
  }

  data2len = compress((const uint8_t *)data, data_len, 
                     data2, data2size, c_format_zlib);
  if ((int)data2len < 0) {
    log_warn("compress failed and returned %lu", (unsigned long)data2len);
    return -1;
  }

  char* temp_out_buf = new char[c_HTTP_PAYLOAD_BUF_SIZE];  // current pointer for output buffer
  op = (char*) temp_out_buf;
  tp = (const char*) cover_payload;  // current pointer for http msg template, replace with payloadbuf?
  plimit = (const char *) (cover_payload+cover_len);

  //vmon: Here obviously the intent was to break data and put it in different chunks 
  //(as the capcaity function suggests but they got lazy and dumped everything in the
  //first chunk
  while (tp < plimit) {
    // find the next stream obj
    streamStart = strInBinary(STREAM_BEGIN, STREAM_BEGIN_SIZE, tp, plimit-tp);
    if (streamStart == NULL) {
      log_warn("Cannot find stream in pdf");
      return -1;
    }

    streamEnd = strInBinary(STREAM_END, STREAM_END_SIZE, tp,  plimit-tp);
    if (streamEnd == NULL) {
      log_warn("Cannot find endstream in pdf");
      return -1;
    }

    filterStart = strInBinaryRewind(" obj", 4, tp, streamStart-tp);
    if (filterStart == NULL) {
      log_warn("Cannot find obj\n");
      delete[] temp_out_buf;
      return -1;
    } else {
      const char stream_meta_data[] = " <<\n/Length %d\n/Filter /FlateDecode\n>>\nstream\n";
      const char end_stream_flag[] = "\nendstream";
      // copy everything between tp and up and and including "obj" to outbuf

      //but first check if we are overflowing our limit
      size = filterStart - tp + 4;
      if (size + strlen(stream_meta_data) + sizeof(int)*(8.0/3.0) + data2len  + (plimit - streamEnd) > c_HTTP_PAYLOAD_BUF_SIZE) {
        log_warn("pdf encoding would results in buffer overflow, tell SRI to fix their encoding to use all available chunks instead of dumping evenything in the first chunk.");
        delete[] temp_out_buf;
        return -1;
      }

      memcpy(op, tp, size);
      op[size] = 0;
      op += size;

      // write meta-data for stream object
      np = sprintf(op, stream_meta_data, (int)data2len);
      if (np < 0) {
        log_warn("sprintf failed\n");
        delete[] temp_out_buf;
        return -1;
      }
      op += np;

      // copy compressed data to outbuf 
      memcpy(op, data2, data2len);
      op += data2len;

      // write endstream to outbuf
      np = sprintf(op, end_stream_flag);
      if (np < 0) {
        log_warn("sprintf failed\n");
        delete[] temp_out_buf;
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

  //now we need to copy the new buffer into what we were given
  size_t  encoded_pdf_size = op - temp_out_buf;
  memcpy(cover_payload, temp_out_buf, encoded_pdf_size);
  delete[]temp_out_buf;
  
  return encoded_pdf_size;

}

ssize_t
PDFSteg::decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data) //const char *data, size_t dlen,
//           char *outbuf, size_t outbufsize...data here is outbuf being passed in!
{
  const char *dp, *dlimit;
  uint8_t *op;
  char *streamStart, *streamEnd;
  size_t cnt, size, size2;
  size_t outbufsize = HTTP_PAYLOAD_BUF_SIZE;

  int streamObjStartSkip=0;
  int streamObjEndSkip=0;

  if (cover_len > SIZE_T_CEILING || outbufsize > SIZE_T_CEILING)
    return -1;

  dp = (const char *) cover_payload;   // current pointer for data
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
    size = (streamEnd-streamObjEndSkip) - dp;

    size2 = decompress((const uint8_t *) dp, size, op, outbufsize);
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



PDFSteg::PDFSteg(PayloadServer* payload_provider, double noise2signal)
 :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_PDF)

{

}
