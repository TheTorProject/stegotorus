/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 * 
 * jsSteg: A Javascript-based steganography module
 *
 */


#include "util.h"
#include "../payload_server.h"
#include "file_steg.h"
#include "jsSteg.h"
#include "compression.h"
#include "connections.h"

#include <ctype.h>

#include <event2/buffer.h>


void buf_dump(unsigned char* buf, int len, FILE *out);

ssize_t JSSteg::headless_capacity(const std::vector<uint8_t>& cover_body)
{
  return max(0, (static_cast<int>(js_code_block_preliminary_capacity(cover_body.begin(), cover_body.size())) - JS_DELIMITER_SIZE)/2);
  // because we use 2 hex char to encode every data byte, the available
  // capacity for encoding data is divided by 2

}

size_t
JSSteg::js_code_block_preliminary_capacity(std::vector<uint8_t>::const_iterator block_start, const size_t block_len)
{
  
  int cnt=0;
  int j;

  auto cur_offset = 0;

  j = offset2Hex(&(*block_start), block_len, 0);
  while (j != -1) {
    cnt++;
    if (j == 0) {
      cur_offset += 1;
    } else {
       cur_offset += j+1;
    }

    j = offset2Hex(&(*(block_start + cur_offset)), block_len - cur_offset, 1);
  }

#ifdef DEBUG
  log_debug("code block has capacity %d", cnt);
#endif
  
  return cnt;
}



/*
 * isGzipContent(char *msg)
 *
 * If the HTTP header of msg specifies that the content is gzipped,
 * this function returns 1; otherwise, it returns 0
 *
 * Assumptions:
 * msg is null terminated
 *
 */
int isGzipContent (char *msg) {
  char *ptr = msg, *end;
  int gzipFlag = 0;

  if (!strstr(msg, "\r\n\r\n"))
    return 0;

  while (1) {
    end = strstr(ptr, "\r\n");
    if (end == NULL) {
      break;
    }

    if (!strncmp(ptr, "Content-Encoding: gzip", 22)) {
      gzipFlag = 1;
      break;
    }

    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

  return gzipFlag;
}


int JSSteg::isGzipContent (char *msg) {
  char *ptr = msg, *end;
  int gzipFlag = 0;

  if (!strstr(msg, "\r\n\r\n"))
    return 0;

  while (1) {
    end = strstr(ptr, "\r\n");
    if (end == NULL) {
      break;
    }

    if (!strncmp(ptr, "Content-Encoding: gzip", 22)) {
      gzipFlag = 1;
      break;
    }

    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

  return gzipFlag;
}


/*
 * offset2Hex returns the offset to the next usable hex char.
 * usable here refer to char that our steg module can use to encode
 * data. in particular, words that correspond to common JavaScript keywords
 * are not used for data encoding (see skipJSPattern). Also, because
 * JS var name must start with an underscore or a letter (but not a digit)
 * we don't use the first char of a word for encoding data
 *
 * e.g., the JS statement "var a;" won't be used for encoding data
 * because "var" is a common JS keyword and "a" is the first char of a word
 *
 * Input:
 * p - ptr to the starting pos 
 * range - max number of char to look
 * isLastCharHex - is the char pointed to by (p-1) a hex char 
 *
 * Output:
 * offset2Hex returns the offset to the next usable hex char
 * between p and (p+range), if it exists;
 * otherwise, it returns -1
 *
 */
int
JSSteg::offset2Hex (const unsigned char *p, int range, int isLastCharHex) {
  const unsigned char *cp = p;
  int i,j;
  int isFirstWordChar = 1;

  if (range < 1) return -1;

  // case 1: last char is hexadecimal
  if (isLastCharHex) {
    if (isxdigit(*cp)) return 0; // base case
    else {
      while (cp < (p+range) && isalnum_(*cp)) {
        cp++;
        if (isxdigit(*cp)) return (cp-p);
      }
      if (cp >= (p+range)) return -1;
      // non-alnum_ found
      // fallthru and handle case 2
    }
  }
 
  // case 2:
  // find the next word that starts with alnum or underscore,
  // which could be a variable, keyword, or literal inside a string

  i = offset2Alnum_(cp, p+range-cp);
  if (i == -1) return -1;

  while (cp < (p+range) && i != -1) {

    if (i == 0) { 
      if (isFirstWordChar) {
        j = skipJSPattern(cp, p+range-cp); 
        if (j > 0) {
          cp = cp+j;
        } else {
          cp++; isFirstWordChar = 0; // skip the 1st char of a word
        }
      } else { // we are in the middle of a word; no need to invoke skipJSPattern
        if (isxdigit(*cp)) return (cp-p);
        if (!isalnum_(*cp)) {
          isFirstWordChar = 1;
        }
        cp++;
     }
   } else {
     cp += i; isFirstWordChar = 1;
   }
   i = offset2Alnum_(cp, p+range-cp);

  } // while

  // cannot find next usable hex char 
  return -1;
 
}

/*
 * findContentType(char *msg)
 *
 * If the HTTP header of msg specifies that the content type:
 * case (content type)
 *   javascript: return HTTP_CONTENT_JAVASCRIPT
 *   pdf:        return HTTP_CONTENT_PDF
 *   shockwave:  return HTTP_CONTENT_SWF
 *   html:       return HTTP_CONTENT_HTML
 *   otherwise:  return 0
 *
 * Assumptions:
 * msg is null terminated
 *
 */
int findContentType (char *msg) {
  char *ptr = msg, *end;

  if (!strstr(msg, "\r\n\r\n"))
    return 0;

  while (1) {
    end = strstr(ptr, "\r\n");
    if (end == NULL) {
      break;
    }

    if (!strncmp(ptr, "Content-Type:", 13)) {

      if (!strncmp(ptr+14, "text/javascript", 15) ||
          !strncmp(ptr+14, "application/javascript", 22) ||
          !strncmp(ptr+14, "application/x-javascript", 24)) {
        return HTTP_CONTENT_JAVASCRIPT;
      }
      if (!strncmp(ptr+14, "text/html", 9)) {
        return HTTP_CONTENT_HTML;
      }
      if (!strncmp(ptr+14, "application/pdf", 15) ||
          !strncmp(ptr+14, "application/x-pdf", 17)) {
        return HTTP_CONTENT_PDF;
      }
      if (!strncmp(ptr+14, "application/x-shockwave-flash", strlen("application/x-shockwave-flash"))) {
        return HTTP_CONTENT_SWF;
      }
    }

    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

  return 0;
}

int JSSteg::findContentType (char *msg) {
  char *ptr = msg, *end;

  if (!strstr(msg, "\r\n\r\n"))
    return 0;

  while (1) {
    end = strstr(ptr, "\r\n");
    if (end == NULL) {
      break;
    }

    if (!strncmp(ptr, "Content-Type:", 13)) {

      if (!strncmp(ptr+14, "text/javascript", 15) ||
          !strncmp(ptr+14, "application/javascript", 22) ||
          !strncmp(ptr+14, "application/x-javascript", 24)) {
        return HTTP_CONTENT_JAVASCRIPT;
      }
      if (!strncmp(ptr+14, "text/html", 9)) {
        return HTTP_CONTENT_HTML;
      }
      if (!strncmp(ptr+14, "application/pdf", 15) ||
          !strncmp(ptr+14, "application/x-pdf", 17)) {
        return HTTP_CONTENT_PDF;
      }
      if (!strncmp(ptr+14, "application/x-shockwave-flash", strlen("application/x-shockwave-flash"))) {
        return HTTP_CONTENT_SWF;
      }
    }

    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

  return 0;
}

/*
 * int encode(char *data, char *jTemplate, char *jData,
 *            unsigned int dlen, unsigned int jtlen, unsigned int jdlen)
 *
 *
 * input:
 *   - data[] : hex data to hide
 *   - dlen   : size of data
 *   - jTemplate[] : Javascript
 *   - jlen   : size of jTemplate
 *   - jdlen  : size of jData, output buffer
 *
 * output:
 *   - jData  : result of encoding data in jTemplate
 */
/*** int encode(char *data, char *jTemplate, char *jData,
           unsigned int dlen, unsigned int jtlen, unsigned int jdlen )
{
  unsigned int encCnt = 0;  
  char *dp, *jtp, *jdp; 

  unsigned int j;

  
  if (jdlen < jtlen) { return INVALID_BUF_SIZE; }

  dp = data; jtp = jTemplate; jdp = jData;

  if (! isxString(dp) ) { return INVALID_DATA_CHAR; }

  
  if (dlen < 1) { return 0; }


  for (j=0; j<jtlen; j++) {
    
    if ( isxdigit(*jtp) ) {
      *jdp = *dp;
      dp++;
      encCnt++;
      if (encCnt == dlen) {
        jtp++; jdp++;
        break;
      }
    } else {
      *jdp = *jtp;
    }
    jtp++; jdp++;
  }


  =
  while (jtp < (jTemplate+jtlen)) {
    *jdp++ = *jtp++;
  }

  return encCnt; 
  }  ***/


#define startScriptTypeJS "<script type=\"text/javascript\">"
#define endScriptTypeJS "</script>"
// #define JS_DELIMITER "?"
// #define JS_DELIMITER_REPLACEMENT "."

ssize_t JSSteg::decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data) /*char *jData, char *dataBuf, unsigned int jdlen,
             unsigned int dataBufSize, int *fin */
{
  int gzipMode = JS_GZIP_RESP;
  ssize_t decCnt;
  int k, fin;
  vector<uint8_t> decompressed_payload(HTTP_PAYLOAD_BUF_SIZE); 

  if (gzipMode) {
    log_debug("gzip content encoding detected");

    //TODO: perhapse we can change decompress to use vectors
    ssize_t decompressed_payload_len = decompress(const_cast<const uint8_t *>(cover_payload.data()), cover_payload.size(),
                                 decompressed_payload.data(), HTTP_PAYLOAD_BUF_SIZE);
    if (decompressed_payload_len <= 0) {
      log_warn("gzInflate for httpBody fails");
      return RECV_BAD;
    }

    //shrink the vecotor to the actual used size
    decompressed_payload.resize(decompressed_payload_len);

  } else {
    decompressed_payload = cover_payload;
  }

  decCnt = decode_http_body(decompressed_payload, data, fin);

  data.push_back(0);

  log_debug("After decodeHTTPBody; decCnt: %zd\n", decCnt);

  // decCnt is an odd number or data is not a hex string
  if (decCnt % 2) {
    log_debug("CLIENT ERROR: An odd number of hex characters received\n");
    return -1;
  }

  if (!isxString((const char*)data.data())) {
    log_debug("CLIENT ERROR: Data received not hex");
    return -1;
  }

  // we are going to decode data in data live!
  // convert hex data back to binary
  char c;
  int i,j;
  for ( i=0, j=0; i< decCnt; i=i+2, ++j) {
    sscanf((char*)&data[i], "%2x", (unsigned int*) &k);
    c = (char)k;
    data[j] = (uint8_t)c;
  }

  //resize data to the actual length
  decCnt /= 2;
  data.resize(decCnt);

  return decCnt;

}

/*
 * similar to encode(), but uses offset2Hex to look for usable hex char
 * in JS for encoding. See offset2Hex for what hex char are considered
 * usable. encode() also converts JS_DELIMITER that appears in the
 * the JS to JS_DELIMITER_REPLACEMENT, before all the data is encoded.
 *
 * Output:
 * fin - signal the caller whether all data has been encoded and
 *       a JS_DELIMITER has been added

 * description:
 *   embed hex-encoded data (data) in the input Javascript (jTemplate)
 *   and put the result in jData
 *   function returns the number of characters in data successfully
 *   embedded in jData, or returns one of the error codes
 *
 * approach:
 *   replaces characters in jTemplate that are hexadecimal (i.e., {0-9,a-f,A-F})
 *   with those in data, and leave the non-hex char in place
 * assumptions:
 *   - data is hex-encoded
 *
 * exceptions:
 *   - if (jdlen < jtlen) return INVALID_BUF_SIZE
 *   - if (data contains non-hex char) return INVALID_DATA_CHAR
 *
 * example:
 *   data      = "0123456789ABCDEF"
 *   jTemplate = "dfp_ord=Math.random()*10000000000000000; dfp_tile = 1;"
 *   encode() returns 16
 *   jData     = "01p_or2=M3th.r4n5om()*6789ABCDEF0000000; dfp_tile = 1;"
 *
 *
 *    @param data: the data to be embeded
 *    @param data_len: the length of the data
 *    @param cover_payload: the cover to embed the data into
 *    @param cover_len: cover size in byte
 *
 *    @return < 0 in case of error or length of the cover with embedded dat at success
 *  
 */
ssize_t
JSSteg::encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payload)
{
  unsigned int cLen, outbuf2len;  /* num of data encoded in jData */

  log_debug("at jssteg encode");
  int gzipMode = JS_GZIP_RESP;
  /*
   *  insanity checks
   */
  //if (jdlen < jtlen) { return INVALID_BUF_SIZE; }
  log_assert(HTTP_PAYLOAD_BUF_SIZE < SIZE_T_CEILING);

  if (cover_payload.size() > SIZE_T_CEILING || data.size() > SIZE_T_CEILING)
    return -1;

  cLen = headless_capacity(cover_payload);
  if (cLen <  data.size()) {
    log_warn("not enough cover capacity to embed data");
    return -1; //not enough capacity is an error because you should have check before requesting
    //However when one use a real time cover server covers might change
  }

  size_t hexed_datalen = 2*data.size();
  std::vector<uint8_t> hexed_data(hexed_datalen);

  //we know that cover_and_data will be of the cover size
  vector<uint8_t> cover_with_data(cover_payload.size());

  encode_data_to_hex(data, hexed_data);

  ssize_t r = encode_http_body(hexed_data, cover_payload, cover_with_data);
  
  if (r < 0 || ((unsigned int) r < hexed_datalen)) {
    log_warn("SERVER ERROR: in data encoding");
    return -1;
  }

  // work in progressn
  if (gzipMode == 1) {
    // conservative estimate:
    // sizeof outbuf2 = cLen + 10-byte for gzip header + 8-byte for crc
    vector<uint8_t> outbuf2;
    outbuf2.resize(cover_with_data.size()+18); //could be overallocated due to differing size of 18 chars and 18 uint8_ts
    outbuf2len = compress(cover_with_data.data(), cover_with_data.size(),
                          outbuf2.data(), cover_with_data.size()+18, c_format_gzip);

    if (outbuf2len <= 0) {
      log_warn("gzDeflate for outbuf fails");
      return -1;
    }
    
    cover_with_data = outbuf2;

  }
  //encCnt isn't really needed any more except for debugging and tracking, but return value outbuf2len is needed for new header
  //return encCnt;
  cover_payload = cover_with_data;
  return cover_with_data.size();

}

/**
   this function carry the only major part that is different between a
   js file and html file. As such html file will re-implement it accordingly
   As the result encode and decode function for both types remains the same.
*/
ssize_t
JSSteg::encode_http_body(const std::vector<uint8_t>& data, const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& cover_and_data)
{
  //Sanity check: we assume that cover_and_data has reserved enough memory
  // to contain cover_paylaoad
  log_assert(cover_and_data.size() >= cover_payload.size());
  log_assert(isxString(reinterpret_cast<const char*>(data.data())));

  int fin;
  //the whole file is a one giant js block so offset is 0 and block size is equal to cover size
  //and the data offset is also zero
  ssize_t r = encode_in_single_js_block(cover_payload.begin(), cover_payload.end(), data.begin(), data.end(), cover_and_data.begin(), fin);

  if (r < 0 || ((unsigned int) r < data.size()) || fin == 0) {
    log_warn("SERVER ERROR: Incomplete data encoding");
    return -1;
  }

  return r;

}

/**
   this function carry the only major part of decoding that is different between a
   js file and html file. As such html file will re-implement it accordingly
   As the result encode and decode function for both types remains the same.

   @param cover_and_data the buffer containing the payload which contains the transported data
   @param data the buffer which will contain extracted data after decoding cover_and_data buffer
   @param fin an indicator signaling success or failure of the decoding

   @return length of recovered data
   
*/
ssize_t
JSSteg::decode_http_body(const std::vector<uint8_t>& cover_and_data, std::vector<uint8_t>& data, int& fin) {
  //In case of js file the whole file is one gian single js block so offset is 0 and the length is the
  //the whole file and data starts from 0
  return decode_single_js_block(cover_and_data.begin(), cover_and_data.end(), data, fin);
}

ssize_t
JSSteg::encode_in_single_js_block(vector<uint8_t>::const_iterator cover_it, vector<uint8_t>::const_iterator  end_of_block, vector<uint8_t>::const_iterator  data_it, vector<uint8_t>::const_iterator  end_of_data, vector<uint8_t>::iterator cover_and_data_it, int& fin)
{
  unsigned int encCnt = 0;  /* num of data encoded in jData */
  int i,j;

  //sanity checks which  must have been checked before
  log_assert(cover_it < end_of_block);
  log_assert(data_it < end_of_data);

  i = offset2Hex(&(*cover_it), end_of_block - cover_it, 0);
  while (data_it < end_of_data && i != -1) {
    // copy next i char from jtp to jdp,
    // except that if *jtp==JS_DELIMITER, copy
    // JS_DELIMITER_REPLACEMENT to jdp instead
    j = 0;
    while (j < i) {
      if (*cover_it == JS_DELIMITER) {
        *cover_and_data_it = JS_DELIMITER_REPLACEMENT;
      } else {
        *cover_and_data_it = *cover_it;
      }
      cover_and_data_it++;
      cover_it++;
      j++;
    }

    *cover_and_data_it = *data_it;
    encCnt++;
    data_it++;
    cover_it++;
    cover_and_data_it++;

    i = offset2Hex(&(*cover_it), end_of_block - cover_it, 1);
  }

  // copy the rest of jTemplate to jdata upto end of
  // the block
  // we have reached here either because we
  // ran out of the data or ran out of usable
  // cover.
  // if we've encoded all data, replace the first
  // char in jTemplate by JS_DELIMITER, if needed,
  // to signal the end of data encoding
  log_debug("encode: encCnt = %d\n", encCnt);

  if (data_it < end_of_data) {
    //we are still left with more data to encode
    fin = 0;

  } else {
    //all data are encoded
    // replace the next char in jTemplate by JS_DELIMITER
    if (cover_it < end_of_block) {
      fin = 1;
      *cover_and_data_it = JS_DELIMITER;
      cover_it++;
      cover_and_data_it++;
    } else {
      //we finished with the data but we don't have a space
      //to indicate that we did so, we set fin = 0 to tell
      //the parent encoder to deal with it
      fin = 0;
    }
  }

  //so we
  //copy the rest of the block 
  while (cover_it < end_of_block) {
    if ((fin == 0) && (*cover_it == JS_DELIMITER)) {
      //and we make sure there is no/misleading delimiter is left on the way
      *cover_and_data_it = JS_DELIMITER_REPLACEMENT;
    } else {
      *cover_and_data_it = *cover_it;
    }
    cover_it++;
    cover_and_data_it++;
  }

  log_debug("encode: encCnt = %dhtml\n", encCnt);
  log_debug("encode: fin= %d\n", fin);

  return encCnt;

}

ssize_t JSSteg::decode_single_js_block(std::vector<uint8_t>::const_iterator cover_and_data_it, const std::vector<uint8_t>::const_iterator end_of_block_pos, std::vector<uint8_t>& data, int& fin)
{
  size_t decCnt = 0;  /* num of data decoded */
  int i,j;
  
  fin = 0;

  i = offset2Hex(&(*cover_and_data_it), end_of_block_pos - cover_and_data_it, 0);
  while (i != -1 ) {
    // return if JS_DELIMITER exists between jdp and jdp+i
    for (j=0; j<i; j++) {
      if (*cover_and_data_it == JS_DELIMITER) {
        fin = 1;
        return decCnt;
      }
      cover_and_data_it++;
    }
    
    // copy hex data from jdp to dp
    data.push_back(*cover_and_data_it);
    cover_and_data_it++;
    decCnt++;

    // find the next hex char
    i = offset2Hex(&(*cover_and_data_it), end_of_block_pos - cover_and_data_it, 1);
  }

  // look for JS_DELIMITER between jdp to jData+jdlen
  while (cover_and_data_it < end_of_block_pos) {
    if (*cover_and_data_it == JS_DELIMITER) {
      fin = 1;
      break;
    }
    cover_and_data_it++;
  }

  return decCnt;
}

void JSSteg::printerr(int err_no) /* name errno had conflict with other vars so I changed it to err_no */
 {
  if (err_no == INVALID_BUF_SIZE) {
    printf ("Error: Output buffer too small\n");
  }
  else if (err_no == INVALID_DATA_CHAR) {
    printf ("Error: Non-hex char in data\n");
  }
  else {
    printf ("Unknown error: %i\n", err_no);
  }
}

JSSteg::JSSteg(PayloadServer& payload_provider, double noise2signal, int content_type)
 :FileStegMod(payload_provider, noise2signal, content_type)
{

}

/*
 * skipJSPattern returns the number of characters to skip when
 * the input pointer matches the start of a common JavaScript
 * keyword 
 *
 * todo: 
 * Use a more efficient regular expression matching algo
 */



int
JSSteg::skipJSPattern(const uint8_t *cp, int len) {
  int i,j;


  char keywords [21][10]= {"function", "return", "var", "int", "random", "Math", "while",
			   "else", "for", "document", "write", "writeln", "true",
			   "false", "True", "False", "window", "indexOf", "navigator", "case", "if"};


  if (len < 1) return 0;

  // change the limit to 21 to enable if as a keyword
  for (i=0; i < 20; i++) {
    char* word = keywords[i];
    
    if (len <= (int) strlen(word))
      continue;

    if (word[0] != cp[0])
      continue;

    for (j=1; j < (int) strlen(word); j++) {
      if (isxdigit(word[j])) {
	if (!isxdigit(cp[j]))
	  goto next_word;
	else
	  continue;
      }
      
      if (cp[j] != word[j])
	goto next_word;
    }
    if (!isalnum(cp[j]) && cp[j] != JS_DELIMITER && cp[j] != JS_DELIMITER_REPLACEMENT)
      return strlen(word)+1;
      
  next_word:
    continue;
  }

  return 0;
}
