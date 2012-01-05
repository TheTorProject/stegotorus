#include "util.h"
#include "payloads.h"
#include "swfSteg.h"


/* These variables below are write-once, hence they should be race-safe */

static int initTypePayload[MAX_CONTENT_TYPE];
static int typePayloadCount[MAX_CONTENT_TYPE];
static int typePayload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
static int typePayloadCap[MAX_CONTENT_TYPE][MAX_PAYLOADS];


static unsigned int max_JS_capacity = 0;
static unsigned int max_HTML_capacity = 0;
static unsigned int max_PDF_capacity = 0;



pentry_header payload_hdrs[MAX_PAYLOADS];
char* payloads[MAX_PAYLOADS];
int payload_count = 0;


unsigned int get_max_JS_capacity() {
  return max_JS_capacity;
}

unsigned int get_max_HTML_capacity() {
  return max_HTML_capacity;
}

unsigned int get_max_PDF_capacity() {
  return max_PDF_capacity;
}



/*
 * fixContentLen corrects the Content-Length for an HTTP msg that
 * has been ungzipped, and removes the "Content-Encoding: gzip"
 * field from the header.
 *
 * The function returns -1 if no change to the HTTP msg has been made,
 * when the msg wasn't gzipped or an error has been encountered
 * If fixContentLen changes the msg header, it will put the new HTTP
 * msg in buf and returns the length of the new msg
 *
 * Input:
 * payload - pointer to the (input) HTTP msg
 * payloadLen - length of the (input) HTTP msg
 *
 * Ouptut:
 * buf - pointer to the buffer containing the new HTTP msg
 * bufLen - length of buf
 * 
 */
int fixContentLen (char* payload, int payloadLen, char *buf, int bufLen) {

  int gzipFlag=0, clFlag=0, clZeroFlag=0;
  char* ptr = payload;
  char* clPtr = payload;
  char* gzipPtr = payload;
  char* end;


  char *cp, *clEndPtr;
  int hdrLen, bodyLen, r, len;





  // note that the ordering between the Content-Length and the Content-Encoding
  // in an HTTP msg may be different for different msg 

  // if payloadLen is larger than the size of our buffer,
  // stop and return -1
  if (payloadLen > bufLen) { return -1; }

  while (1) {
    end = strstr(ptr, "\r\n");
    if (end == NULL) {
      // log_debug("invalid header %d %d %s \n", payloadLen, (int) (ptr - payload), payload);
      return -1;
    }

    if (!strncmp(ptr, "Content-Encoding: gzip\r\n", 24)) {
        gzipFlag = 1;
        gzipPtr = ptr;     
    } else if (!strncmp(ptr, "Content-Length: 0", 17)) {
        clZeroFlag = 1;
    } else if (!strncmp(ptr, "Content-Length:", 15)) {
        clFlag = 1;
        clPtr = ptr;
    }

    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

  // stop if zero Content-Length or Content-Length not found
  if (clZeroFlag || ! clFlag) return -1;
  
  // end now points to the end of the header, before "\r\n\r\n"
  cp=buf;
  bodyLen = (int)(payloadLen - (end+4-payload));

  clEndPtr = strstr(clPtr, "\r\n");
  if (clEndPtr == NULL) {
    log_debug("unable to find end of line for Content-Length");
    return -1;
  }
  if (gzipFlag && clFlag) {
    if (gzipPtr < clPtr) { // Content-Encoding appears before Content-Length

      // copy the part of the header before Content-Encoding
      len = (int)(gzipPtr-payload);
      memcpy(cp, payload, len);
      cp = cp+len;

      // copy the part of the header between Content-Encoding and Content-Length
      // skip 24 char, the len of "Content-Encoding: gzip\r\n"
      // *** this is temporary; we'll remove this after the obfsproxy can perform gzip
      len = (int)(clPtr-(gzipPtr+24));  
      memcpy(cp, gzipPtr+24, len);
      cp = cp+len;

      // put the new Content-Length
      memcpy(cp, "Content-Length: ", 16);
      cp = cp+16;
      r = sprintf(cp, "%d\r\n", bodyLen);
      if (r < 0) {
        log_debug("sprintf fails");
        return -1;
      }
      cp = cp+r;

      // copy the part of the header after Content-Length, if any
      if (clEndPtr != end) { // there is header info after Content-Length
        len = (int)(end-(clEndPtr+2));
        memcpy(cp, clEndPtr+2, len);
        cp = cp+len;
        memcpy(cp, "\r\n\r\n", 4);
        cp = cp+4;
      } else { // Content-Length is the last hdr field
        memcpy(cp, "\r\n", 2);
        cp = cp+2;
      }

      hdrLen = cp-buf;

/****
log_debug("orig: hdrLen = %d, bodyLen = %d, payloadLen = %d", (int)(end+4-payload), bodyLen, payloadLen);
log_debug("new: hdrLen = %d, bodyLen = %d, payloadLen = %d", hdrLen, bodyLen, hdrLen+bodyLen);
 ****/

      // copy the HTTP body
      memcpy(cp, end+4, bodyLen);
      return (hdrLen+bodyLen);

    } else { // Content-Length before Content-Encoding
      // copy the part of the header before Content-Length
      len = (int)(clPtr-payload);
      memcpy(cp, payload, len);
      cp = cp+len;

      // put the new Content-Length
      memcpy(cp, "Content-Length: ", 16);
      cp = cp+16;
      r = sprintf(cp, "%d\r\n", bodyLen);
      if (r < 0) {
        log_debug("sprintf fails");
        return -1;
      }
      cp = cp+r;

      // copy the part of the header between Content-Length and Content-Encoding
      len = (int)(gzipPtr-(clEndPtr+2));
      memcpy(cp, clEndPtr+2, len);
      cp = cp+len;
      
      // copy the part of the header after Content-Encoding
      // skip 24 char, the len of "Content-Encoding: gzip\r\n"
      // *** this is temporary; we'll remove this after the obfsproxy can perform gzip
      if (end > (gzipPtr+24)) { // there is header info after Content-Encoding
        len = (int)(end-(gzipPtr+24));
        memcpy(cp, gzipPtr+24, len);
        cp = cp+len;
        memcpy(cp, "\r\n\r\n", 4);
        cp = cp+4;
      } else { // Content-Encoding is the last field in the hdr
        memcpy(cp, "\r\n", 2);
        cp = cp+2;
      }
      hdrLen = cp-buf;

/****
log_debug("orig: hdrLen = %d, bodyLen = %d, payloadLen = %d", (int)(end+4-payload), bodyLen, payloadLen);
log_debug("new: hdrLen = %d, bodyLen = %d, payloadLen = %d", hdrLen, bodyLen, hdrLen+bodyLen);
 ****/

      // copy the HTTP body
      memcpy(cp, end+4, bodyLen);
      return (hdrLen+bodyLen);
    }
  }
  return -1;
}

void load_payloads(const char* fname) {
  FILE* f;
  char buf[HTTP_MSG_BUF_SIZE];
  char buf2[HTTP_MSG_BUF_SIZE];
  pentry_header pentry;
  int pentryLen;
  int r;

  if (payload_count != 0)
    return;

  srand(time(NULL));
  f = fopen(fname, "r");
  if (f == NULL) {
    fprintf(stderr, "Cannot open trace file %s. Exiting\n", fname);
    exit(1);
  }

  bzero(payload_hdrs, sizeof(payload_hdrs));

  while (payload_count < MAX_PAYLOADS) {

    if (fread(&pentry, 1, sizeof(pentry_header), f) < sizeof(pentry_header)) {
      break;
    }
   
    pentryLen = ntohl(pentry.length);
    if((unsigned int) pentryLen > sizeof(buf)) {
#ifdef DEBUG
      // fprintf(stderr, "pentry too big %d %d\n", pentry.length, ntohl(pentry.length));
      fprintf(stderr, "pentry too big %d\n", pentryLen);
#endif
      // skip to the next pentry
      if (fseek(f, pentryLen, SEEK_CUR)) {
        fprintf(stderr, "skipping to next pentry fails\n");
      }
      continue;
      // exit(0);
    }

    pentry.length = pentryLen;
    pentry.ptype = ntohs(pentry.ptype);

    if (fread(buf, 1, pentry.length, f) < (unsigned int) pentry.length)
      break;

    // todo:
    // fixed content length for gzip'd HTTP msg
    // fixContentLen returns -1, if no change to the msg
    // otherwise, it put the new HTTP msg (with hdr changed) in buf2
    // and returns the size of the new msg

    r = -1;
    if (pentry.ptype == TYPE_HTTP_RESPONSE) {
      r = fixContentLen (buf, pentry.length, buf2, HTTP_MSG_BUF_SIZE);
      // log_debug("for payload_count %d, fixContentLen returns %d", payload_count, r);
    }
    // else {
    // log_debug("for payload_count %d, pentry.ptype = %d", payload_count, pentry.ptype);
    // }

    if (r < 0) {
      payloads[payload_count] = (char *)xmalloc(pentry.length + 1);
      memcpy(payloads[payload_count], buf, pentry.length);
    } else {
      pentry.length = r;
      payloads[payload_count] = (char *)xmalloc(pentry.length + 1);
      memcpy(payloads[payload_count], buf2, pentry.length);
    }
    payload_hdrs[payload_count] = pentry;
    payloads[payload_count][pentry.length] = 0;
    payload_count++;
  } // while

#ifdef DEBUG
  printf("loading payload count = %d\n", payload_count);
#endif
  
  fclose(f);
}





void gen_rfc_1123_date(char* buf, int buf_size) {
  time_t t = time(NULL);
  struct tm *my_tm = gmtime(&t);
  strftime(buf, buf_size, "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", my_tm);
}



void gen_rfc_1123_expiry_date(char* buf, int buf_size) {
  time_t t = time(NULL) + rand() % 10000;
  struct tm *my_tm = gmtime(&t);
  strftime(buf, buf_size, "Expires: %a, %d %b %Y %H:%M:%S GMT\r\n", my_tm);
}





int gen_response_header(char* content_type, int gzip, int length, char* buf, int buflen) {
  char* ptr;

  // conservative assumption here.... 
  if (buflen < 400) {
    fprintf(stderr, "gen_response_header: buflen too small\n");
    return -1;
  }

  sprintf(buf, "HTTP/1.1 200 OK\r\n");
  ptr = buf + strlen("HTTP/1.1 200 OK\r\n");
  gen_rfc_1123_date(ptr, buflen - (ptr - buf));
  ptr = ptr + strlen(ptr);

  sprintf(ptr, "Server: Apache\r\n");
  ptr = ptr + strlen(ptr);

  switch(rand() % 9) {
  case 1:
    sprintf(ptr, "Vary: Cookie\r\n");
    ptr = ptr + strlen(ptr);
    break;

  case 2:
    sprintf(ptr, "Vary: Accept-Encoding, User-Agent\r\n");
    ptr = ptr + strlen(ptr);
    break;

  case 3:
    sprintf(ptr, "Vary: *\r\n");
    ptr = ptr + strlen(ptr);
    break;

  }


  switch(rand() % 4) {
  case 2:
    gen_rfc_1123_expiry_date(ptr, buflen - (ptr - buf));
    ptr = ptr + strlen(ptr);
  }


  

  if (gzip) 
    sprintf(ptr, "Content-Length: %d\r\nContent-Encoding: gzip\r\nContent-Type: %s\r\n", length, content_type);
  else
    sprintf(ptr, "Content-Length: %d\r\nContent-Type: %s\r\n", length, content_type);
    
  ptr += strlen(ptr);

  switch(rand() % 4) {
  case 2:
  case 3:
  case 4:
    sprintf(ptr, "Connection: Keep-Alive\r\n\r\n");
    break;
  default:
    sprintf(ptr, "Connection: close\r\n\r\n");
    break;    
  }

  ptr += strlen(ptr);

  return ptr - buf;
}






int parse_client_headers(char* inbuf, char* outbuf, int len) {
  // client-side
  // remove Host: field
  // remove referrer fields?

  char* ptr = inbuf;
  int outlen = 0;

  while (1) {
    // char* end = strstr(ptr, "\r\n", len - (ptr - inbuf));
    char* end = strstr(ptr, "\r\n");
    if (end == NULL) {
      fprintf(stderr, "invalid client header %d %d %s \n PTR = %s\n", len, (int) (len - (ptr - inbuf)), inbuf, ptr);
      // fprintf(stderr, "HERE %s\n", ptr);
      break;
    }

    if (!strncmp(ptr, "Host:", 5) ||
	!strncmp(ptr, "Referer:", 8) ||
	!strncmp(ptr, "Cookie:", 7)) {
      goto next;
    }

    memcpy(outbuf + outlen, ptr, end - ptr + 2);
    outlen += end - ptr + 2;

  next:
    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }
  
  return outlen;

  // server-side
  // fix date fields
  // fix content-length



}




/* first line is of the form....
   GET /XX/XXXX.swf[?YYYY] HTTP/1.1\r\n
*/


int 
find_uri_type(char* buf_orig, int buflen) {

  char* uri;
  char* ext;

  char* buf = (char *)xmalloc(buflen+1);
  char* uri_end;


  memcpy(buf, buf_orig, buflen);
  buf[buflen] = 0;

  
  if (strncmp(buf, "GET", 3) != 0
      && strncmp(buf, "POST", 4) != 0) {
    fprintf(stderr, "HERE %s\n", buf);
    return -1;
  }
  


  uri = strchr(buf, ' ') + 1;

  if (uri == NULL) {
    fprintf(stderr, "Invalid URL\n");
    return -1;
  }

  uri_end = strchr(uri, ' ');

  if (uri_end == NULL) {
    fprintf(stderr, "unterminated uri\n");
    return -1;
  }

  uri_end[0] = 0;
  




  ext = strrchr(uri, '/');

  if (ext == NULL) {
    fprintf(stderr, "no / in url: find_uri_type...");
    return -1;
  }

  ext = strchr(ext, '.');


  if (ext == NULL || !strncmp(ext, ".html", 5) || !strncmp(ext, ".htm", 4) || !strncmp(ext, ".php", 4)
      || !strncmp(ext, ".jsp", 4) || !strncmp(ext, ".asp", 4))
    return HTTP_CONTENT_HTML;


  if (!strncmp(ext, ".js", 3) || !strncmp(ext, ".JS", 3))
    return HTTP_CONTENT_JAVASCRIPT;

  if (!strncmp(ext, ".pdf", 4) || !strncmp(ext, ".PDF", 4))
    return HTTP_CONTENT_PDF;


  if (!strncmp(ext, ".swf", 4) || !strncmp(ext, ".SWF", 4))
    return HTTP_CONTENT_SWF;



  free(buf);
  return -1;
  
}

/*
int 
find_uri_type(char* buf) {

  char* uri;
  int uri_len;
  char* ext;

  if (strncmp(buf, "GET", 3) != 0 && strncmp(buf, "POST", 4) != 0) 
    return -1;

  buf = strchr(buf, ' ') + 1;
  uri_len = strchr(buf, ' ') - buf;
  uri = xmalloc(uri_len + 1);

  strncpy(uri, buf, uri_len);
  uri[uri_len] = 0;

  if (strchr(uri, '?'))
    ext = strchr(uri, '?') - 4;
  else
    ext = uri + uri_len - 4;


  if (!strncmp(ext, ".pdf", 4) || !strncmp(ext, ".PDF", 4))
    return HTTP_CONTENT_PDF;

  if (!strncmp(ext, ".swf", 4) || !strncmp(ext, ".SWF", 4))
    return HTTP_CONTENT_SWF;

  if (!strncmp(ext, ".js", 3) || !strncmp(ext, ".JS", 3))
    return HTTP_CONTENT_JAVASCRIPT;

  if (!strncmp(ext-1, "html", 4) || !strncmp(ext, "htm", 3) || strchr(ext-1, '.') == NULL)
    return HTTP_CONTENT_HTML;

  // default type
  return HTTP_CONTENT_HTML;
  // return HTTP_CONTENT_JAVASCRIPT;
  return -1;
  
}

*/








unsigned int find_client_payload(char* buf, int len, int type) {
  int r = rand() % payload_count;
  int cnt = 0;
  char* inbuf;

#ifdef DEBUG
  fprintf(stderr, "TRYING payload %d \n", r);
#endif
  while (1) {
    pentry_header* p = &payload_hdrs[r];
    if (p->ptype == type) {
      inbuf = payloads[r];
      if (find_uri_type(inbuf, p->length) != HTTP_CONTENT_SWF &&
          find_uri_type(inbuf, p->length) != HTTP_CONTENT_HTML &&
	  find_uri_type(inbuf, p->length) != HTTP_CONTENT_JAVASCRIPT &&
	  find_uri_type(inbuf, p->length) != HTTP_CONTENT_PDF) {
	goto next;
      }
      if (p->length > len) {
	fprintf(stderr, "BUFFER TOO SMALL... \n");
	goto next;
      }
      else
	len = p->length;
      break;
    }
  next:
    r = (r+1) % payload_count;
    

    // no matching payloads...
    if (cnt++ == payload_count) {
      fprintf(stderr, "NO MATCHING PAYLOADS... \n");
      return 0;
    }
  }

  inbuf[len] = 0;

  // clean up the buffer...
  return parse_client_headers(inbuf, buf, len);
  
}


/*
 * skipJSPattern returns the number of characters to skip when
 * the input pointer matches the start of a common JavaScript
 * keyword 
 *
 * todo: 
 * Use a more efficient regular expression matching algo
 */



int skipJSPattern(char *cp, int len) {
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




/* int skipJSPattern (char *cp, int len) { */

/*   // log_debug("Turning off skipJSPattern for debugging"); */
/*   //  return 0; */

/*   if (len < 1) return 0; */

/*   if (len > 8) { */
/*     // "function " and "function(" */
/*     if (cp[0] == 'f' && */
/*         !strncmp(cp+1, "un", 2) && */
/*         isxdigit(cp[3]) && */
/*         !strncmp(cp+4, "tion", 4) && */
/*         (cp[8] == ' ' || cp[8] == '(')) */
/*     return 9; */
/*   } */

/*   if (len > 6) { */
/*     // "return " */
/*     if (cp[0] == 'r' && */
/*         isxdigit(cp[1]) && */
/*         !strncmp(cp+2, "turn ", 5))  */
/*     return 7; */
/*     // "switch " */
/*     if (cp[0] == 's' && */
/*         !strncmp(cp+1, "wit", 3) && */
/*         isxdigit(cp[4]) && */
/*         !strncmp(cp+5, "h ", 2))  */
/*     return 7; */
/*   } */

/*   if (len > 5) { */
/*     // "while " and "while(" */
/*     if (cp[0] == 'w' && */
/*         !strncmp(cp+1, "hil", 3) && */
/*         isxdigit(cp[4]) && */
/*         (cp[5] == ' ' || cp[5] == '(')) */
/*     return 6; */
/*   } */

/*   if (len > 4) { */
/*     // "else " and "else{" */
/*     if (cp[0] == 'e' && */
/*         !strncmp(cp, "ls", 2) && */
/*         isxdigit(cp[3]) && */
/*         (cp[4] == ' ' || cp[4] == '{')) */
/*     return 5; */
/*   } */

/*   if (len > 3) { */
/*     // "var " */
/*     if (cp[0] == 'v' && */
/*         isxdigit(cp[1]) && */
/*         cp[2] == 'r' && */
/*         cp[3] == ' ') */
/*     return 4; */
/*   } */

/*   return 0; */
/* } */



int isalnum_ (char c) {
  if (isalnum(c) || c == '_') return 1;
  else return 0;
}

int offset2Alnum_ (char *p, int range) {
  char *cp = p;

  while ((cp < (p+range)) && !isalnum_(*cp)) {
    cp++;
  }

  if (cp < (p+range)) {
    return (cp-p);
  } else {
    return -1;
  }
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
int offset2Hex (char *p, int range, int isLastCharHex) {
  char *cp = p;
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
        if (! isalnum_(*cp)) {
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
 * capacityJS3 is the next iteration for capacityJS
 */
unsigned int capacityJS3 (char* buf, int len, int mode) {
  char *hEnd, *bp, *jsStart, *jsEnd;
  int cnt=0;
  int j;

  // jump to the beginning of the body of the HTTP message
  hEnd = strstr(buf, "\r\n\r\n");
  if (hEnd == NULL) {
    // cannot find the separator between HTTP header and HTTP body
    return 0;
  }
  bp = hEnd + 4;


  if (mode == CONTENT_JAVASCRIPT) {
    j = offset2Hex(bp, (buf+len)-bp, 0);
    while (j != -1) {
      cnt++;
      if (j == 0) {
        bp = bp+1;
      } else {
        bp = bp+j+1;
      }

      if (len < buf + len - bp) {
	fprintf(stderr, "HERE\n");
      }
      j = offset2Hex(bp, (buf+len)-bp, 1);
    } // while
    return cnt;
  } else if (mode == CONTENT_HTML_JAVASCRIPT) {
     while (bp < (buf+len)) {
       jsStart = strstr(bp, "<script type=\"text/javascript\">");
       if (jsStart == NULL) break;
       bp = jsStart+31;
       jsEnd = strstr(bp, "</script>");
       if (jsEnd == NULL) break;
       // count the number of usable hex char between jsStart+31 and jsEnd

       j = offset2Hex(bp, jsEnd-bp, 0);
       while (j != -1) {
         cnt++;
         if (j == 0) {
           bp = bp+1;
         } else {
           bp = bp+j+1;
         }

	 if (len < jsEnd - buf || len < jsEnd - bp) {
	   fprintf(stderr, "HERE2\n");
	 }


         j = offset2Hex(bp, jsEnd-bp, 1);
       } // while (j != -1)

       if (buf + len < bp + 9) {
	 fprintf(stderr, "HERE3\n");
       }


       bp += 9;
     } // while (bp < (buf+len))
     return cnt;
  } else {
    fprintf(stderr, "Unknown mode (%d) for capacityJS() ... \n", mode);
    return 0;
  }
}


/*
 * strInBinary looks for char array pattern of length patternLen in a char array
 * blob of length blobLen
 *
 * return a pointer for the first occurrence of pattern in blob, if found
 * otherwise, return NULL
 * 
 */
char *
strInBinary (const char *pattern, unsigned int patternLen, 
             const char *blob, unsigned int blobLen) {
  int found = 0;
  char *cp = (char *)blob;

  while (1) {
    if (blob+blobLen-cp < (int) patternLen) break;
    if (*cp == pattern[0]) {
      if (memcmp(cp, pattern, patternLen) == 0) {
        found = 1;
        break;
      }
    }
    cp++; 
  }
  if (found) return cp;
  else return NULL;
}


/*
 * has_eligible_HTTP_content() identifies if the input HTTP message 
 * contains a specified type of content, used by a steg module to
 * select candidate HTTP message as cover traffic
 */

// for JavaScript, there are two cases:
// 1) If Content-Type: has one of the following values
//       text/javascript 
//       application/x-javascript
//       application/javascript
// 2) Content-Type: text/html and 
//    HTTP body contains <script type="text/javascript"> ... </script>
// #define CONTENT_JAVASCRIPT		1 (for case 1)
// #define CONTENT_HTML_JAVASCRIPT	2 (for case 2)
//
// for pdf, we look for the msgs whose Content-Type: has one of the
// following values
// 1) application/pdf
// 2) application/x-pdf
// 

int has_eligible_HTTP_content (char* buf, int len, int type) {
  char* ptr = buf;
  char* matchptr;
  int tjFlag=0, thFlag=0, ceFlag=0, teFlag=0, http304Flag=0, clZeroFlag=0, pdfFlag=0, swfFlag=0; //, gzipFlag=0; // compiler under Ubuntu complains about unused vars, so commenting out until we need it
  char* end, *cp;

#ifdef DEBUG
  fprintf(stderr, "TESTING availabilty of js in payload ... \n");
#endif

  if (type != HTTP_CONTENT_JAVASCRIPT &&
      type != HTTP_CONTENT_HTML &&
      type != HTTP_CONTENT_PDF && type != HTTP_CONTENT_SWF)
    return 0;

  // assumption: buf is null-terminated
  if (!strstr(buf, "\r\n\r\n"))
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
	tjFlag = 1;
      }
      if (!strncmp(ptr+14, "text/html", 9)) {
	thFlag = 1;
      }
      if (!strncmp(ptr+14, "application/pdf", 15) || 
	  !strncmp(ptr+14, "application/x-pdf", 17)) {
	pdfFlag = 1;
      }
      if (!strncmp(ptr+14, "application/x-shockwave-flash", strlen("application/x-shockwave-flash"))) {
	swfFlag = 1;
      }

    } else if (!strncmp(ptr, "Content-Encoding: gzip", 22)) {
      //      gzipFlag = 1; // commented out as variable is set but never read and Ubuntu compiler complains
    } else if (!strncmp(ptr, "Content-Encoding:", 17)) { // Content-Encoding that is not gzip
      ceFlag = 1;
    } else if (!strncmp(ptr, "Transfer-Encoding:", 18)) {
      teFlag = 1;
    } else if (!strncmp(ptr, "HTTP/1.1 304 ", 13)) {
      http304Flag = 1;
    } else if (!strncmp(ptr, "Content-Length: 0", 17)) {
      clZeroFlag = 1;
    }
    
    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

#ifdef DEBUG
  printf("tjFlag=%d; thFlag=%d; gzipFlag=%d; ceFlag=%d; teFlag=%d; http304Flag=%d; clZeroFlag=%d\n", 
    tjFlag, thFlag, gzipFlag, ceFlag, teFlag, http304Flag, clZeroFlag);
#endif

  // if (type == HTTP_CONTENT_JAVASCRIPT)
  if (type == HTTP_CONTENT_JAVASCRIPT || type == HTTP_CONTENT_HTML) {
    // empty body if it's HTTP not modified (304) or zero Content-Length
    if (http304Flag || clZeroFlag) return 0; 

    // for now, we're not dealing with Transfer-Encoding (e.g., chunked)
    // or Content-Encoding that is not gzip
    // if (teFlag) return 0;
    if (teFlag || ceFlag) return 0;

    if (tjFlag && ceFlag && end != NULL) {
      log_debug("(JS) gzip flag detected with hdr len %d", (int)(end-buf+4));
    } else if (thFlag && ceFlag && end != NULL) {
      log_debug("(HTML) gzip flag detected with hdr len %d", (int)(end-buf+4));
    }

    // case 1
    if (tjFlag) return 1; 

    // case 2: check if HTTP body contains <script type="text/javascript">
    if (thFlag) {
      matchptr = strstr(ptr, "<script type=\"text/javascript\">");
      if (matchptr != NULL) {
        return 2;
      }
    }
  }

  if (type == HTTP_CONTENT_PDF && pdfFlag) {
    // reject msg with empty body: HTTP not modified (304) or zero Content-Length
    if (http304Flag || clZeroFlag) return 0; 

    // for now, we're not dealing with Transfer-Encoding (e.g., chunked)
    // or Content-Encoding that is not gzip
    // if (teFlag) return 0;
    if (teFlag || ceFlag) return 0;

    // check if HTTP body contains "endstream";
    // strlen("endstream") == 9
    
    cp = strInBinary("endstream", 9, ptr, buf+len-ptr);
    if (cp != NULL) {
      // log_debug("Matched endstream!");
      return 1;
    }
  }
  
  if (type == HTTP_CONTENT_SWF && swfFlag == 1 && 
      ((len + buf - end) > SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 8))
    return 1;

  return 0;
}



unsigned int capacityPDF (char* buf, int len) {
  char *hEnd, *bp, *streamStart, *streamEnd;
  int cnt=0;
  int size;

  // jump to the beginning of the body of the HTTP message
  hEnd = strstr(buf, "\r\n\r\n");
  if (hEnd == NULL) {
    // cannot find the separator between HTTP header and HTTP body
    return 0;
  }
  bp = hEnd + 4;

  while (bp < (buf+len)) {
     streamStart = strInBinary("stream", 6, bp, (buf+len)-bp);
     // streamStart = strstr(bp, "stream");
     if (streamStart == NULL) break;
     bp = streamStart+6;
     streamEnd = strInBinary("endstream", 9, bp, (buf+len)-bp);
     // streamEnd = strstr(bp, "endstream");
     if (streamEnd == NULL) break;
     // count the number of char between streamStart+6 and streamEnd
     size = streamEnd - (streamStart+6) - 2; // 2 for \r\n before streamEnd
     if (size > 0) {
       cnt = cnt + size;
       log_debug("capacity of pdf increase by %d", size);
     }
     bp += 9;
  }
  return cnt;
}









/*
 * init_payload_pool initializes the arrays pertaining to 
 * message payloads for the specified content type
 *
 * Specifically, it populates the following arrays
 * static int initTypePayload[MAX_CONTENT_TYPE];
 * static int typePayloadCount[MAX_CONTENT_TYPE];
 * static int typePayload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
 * static int typePayloadCap[MAX_CONTENT_TYPE][MAX_PAYLOADS];
 *
 * Input:
 * len - max length of payload
 * type - ptype field value in pentry_header
 * contentType - (e.g, HTTP_CONTENT_JAVASCRIPT for JavaScript content)
 */




int  init_JS_payload_pool(int len, int type, int minCapacity) {

  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0; 
  int sumPayloadSize = 0;
  int minPayloadCap = 0, maxPayloadCap = 0;
  int sumPayloadCap = 0;

  unsigned int contentType = HTTP_CONTENT_JAVASCRIPT;

  int cnt = 0;
  int r;
  pentry_header* p;
  char* msgbuf;
  int cap;
  int mode;



  if (payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?\n");
    return 0;
  }
  
  if (initTypePayload[contentType] != 0) return 1; // init is done already


  for (r = 0; r < payload_count; r++) {
    p = &payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_JAVASCRIPT);
    if (mode == CONTENT_JAVASCRIPT) {
      
      cap = capacityJS3(msgbuf, p->length, mode);
      if (cap <  JS_DELIMITER_SIZE) 
	continue;

      cap = (cap - JS_DELIMITER_SIZE)/2;

      if (cap > minCapacity) {
	typePayloadCap[contentType][cnt] = cap; // (cap-JS_DELIMITER_SIZE)/2;
	// because we use 2 hex char to encode every data byte, the available
	// capacity for encoding data is divided by 2
	typePayload[contentType][cnt] = r;
	cnt++;
	
	// update stat
	if (cnt == 1) {
	  minPayloadSize = p->length; maxPayloadSize = p->length;
	  minPayloadCap = cap; maxPayloadCap = cap;
	} 
	else {
	  if (minPayloadSize > p->length) minPayloadSize = p->length; 
	  if (maxPayloadSize < p->length) maxPayloadSize = p->length; 
	  if (minPayloadCap > cap) minPayloadCap = cap;
	  if (maxPayloadCap < cap) {
	    maxPayloadCap = cap;
	  }
	  
	}
	sumPayloadSize += p->length; sumPayloadCap += cap;
      }
    }
  }

  
  max_JS_capacity = maxPayloadCap;


  initTypePayload[contentType] = 1;
  typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  log_debug("minPayloadCap  = %d", minPayloadCap); 
  log_debug("maxPayloadCap  = %d", maxPayloadCap); 
  log_debug("avgPayloadCap  = %f", (float)sumPayloadCap/(float)cnt); 
  return 1;
}


int  init_HTML_payload_pool(int len, int type, int minCapacity) {

  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0; 
  int sumPayloadSize = 0;
  int minPayloadCap = 0, maxPayloadCap = 0;
  int sumPayloadCap = 0;

  unsigned int contentType = HTTP_CONTENT_HTML;

  int cnt = 0;
  int r;
  pentry_header* p;
  char* msgbuf;
  int cap;
  int mode;



  if (payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?\n");
    return 0;
  }
  
  if (initTypePayload[contentType] != 0) return 1; // init is done already


  for (r = 0; r < payload_count; r++) {
    p = &payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_HTML);
    if (mode == CONTENT_HTML_JAVASCRIPT) {
      
      cap = capacityJS3(msgbuf, p->length, mode);
      if (cap <  JS_DELIMITER_SIZE) 
	continue;

      cap = (cap - JS_DELIMITER_SIZE)/2;

      if (cap > minCapacity) {
	typePayloadCap[contentType][cnt] = cap; // (cap-JS_DELIMITER_SIZE)/2;
	// because we use 2 hex char to encode every data byte, the available
	// capacity for encoding data is divided by 2
	typePayload[contentType][cnt] = r;
	cnt++;
	
	// update stat
	if (cnt == 1) {
	  minPayloadSize = p->length; maxPayloadSize = p->length;
	  minPayloadCap = cap; maxPayloadCap = cap;
	} 
	else {
	  if (minPayloadSize > p->length) minPayloadSize = p->length; 
	  if (maxPayloadSize < p->length) maxPayloadSize = p->length; 
	  if (minPayloadCap > cap) minPayloadCap = cap;
	  if (maxPayloadCap < cap) {
	    maxPayloadCap = cap;
	  }
	  
	}
	sumPayloadSize += p->length; sumPayloadCap += cap;
      }
    }
  }

  
  max_HTML_capacity = maxPayloadCap;


  initTypePayload[contentType] = 1;
  typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  log_debug("minPayloadCap  = %d", minPayloadCap); 
  log_debug("maxPayloadCap  = %d", maxPayloadCap); 
  log_debug("avgPayloadCap  = %f", (float)sumPayloadCap/(float)cnt); 
  return 1;
}








int  init_PDF_payload_pool(int len, int type, int minCapacity) {

  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0; 
  int sumPayloadSize = 0;
  int minPayloadCap = 0, maxPayloadCap = 0;
  int sumPayloadCap = 0;

  int cnt = 0;
  int r;
  pentry_header* p;
  char* msgbuf;
  int cap;
  int mode;
  unsigned int contentType = HTTP_CONTENT_PDF;
  

  if (payload_count == 0) {
     fprintf(stderr, "payload_count == 0; forgot to run load_payloads()?\n");
     return 0;
  }
  
  if (initTypePayload[contentType] != 0) return 1; // init is done already


  for (r = 0; r < payload_count; r++) {
    p = &payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_PDF);
    if (mode > 0) {
      // use capacityPDF() to find out the amount of data that we
      // can encode in the pdf doc 
      // cap = minCapacity+1;
      cap = capacityPDF(msgbuf, p->length);
      log_debug("got pdf (index %d) with capacity %d", r, cap);
      if (cap > minCapacity) {
	log_debug("pdf (index %d) greater than mincapacity %d", cnt, minCapacity);
	typePayloadCap[contentType][cnt] = (cap-PDF_DELIMITER_SIZE)/2;
	typePayload[contentType][cnt] = r;
	cnt++;
	
	// update stat
	if (cnt == 1) {
	  minPayloadSize = p->length; maxPayloadSize = p->length;
	  minPayloadCap = cap; maxPayloadCap = cap;
	} 
	else {
	  if (minPayloadSize > p->length) minPayloadSize = p->length; 
	  if (maxPayloadSize < p->length) maxPayloadSize = p->length; 
	  if (minPayloadCap > cap) minPayloadCap = cap;
	  if (maxPayloadCap < cap) maxPayloadCap = cap;
	}
	sumPayloadSize += p->length; sumPayloadCap += cap;
      }
    }
  }

  max_PDF_capacity = maxPayloadCap;
  initTypePayload[contentType] = 1;
  typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  log_debug("minPayloadCap  = %d", minPayloadCap); 
  log_debug("maxPayloadCap  = %d", maxPayloadCap); 
  log_debug("avgPayloadCap  = %f", (float)sumPayloadCap/(float)cnt); 
  return 1;
}





int  init_SWF_payload_pool(int len, int type, int /*unused */) {

  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0; 
  int sumPayloadSize = 0;

  int cnt = 0;
  int r;
  pentry_header* p;
  char* msgbuf;
  int mode;
  unsigned int contentType = HTTP_CONTENT_SWF;


  if (payload_count == 0) {
     fprintf(stderr, "payload_count == 0; forgot to run load_payloads()?\n");
     return 0;
  }
  
  if (initTypePayload[contentType] != 0) return 1; // init is done already


  for (r = 0; r < payload_count; r++) {
    p = &payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = payloads[r];
    // found a payload corr to the specified contentType

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_SWF);
    if (mode > 0) {
      typePayload[contentType][cnt] = r;
      cnt++;
      // update stat
      if (cnt == 1) {
	minPayloadSize = p->length; 
	maxPayloadSize = p->length;
      } 
      else {
	if (minPayloadSize > p->length) 
	  minPayloadSize = p->length; 
	if (maxPayloadSize < p->length) 
	  maxPayloadSize = p->length; 
      }
      sumPayloadSize += p->length;
    }
  }
    
  initTypePayload[contentType] = 1;
  typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  return 1;
}









int get_next_payload (int contentType, char** buf, int* size, int* cap) {
  int r;

  log_debug("get_next_payload: contentType = %d, initTypePayload = %d, typePayloadCount = %d",
      contentType, initTypePayload[contentType], typePayloadCount[contentType]);


  if (contentType <= 0 ||
      contentType >= MAX_CONTENT_TYPE ||
      initTypePayload[contentType] == 0 ||
      typePayloadCount[contentType] == 0)
    return 0;

  r = rand() % typePayloadCount[contentType];
//  int r = 1;
//  log_debug("SERVER: *** always choose the same payload ***");

  log_debug("SERVER: picked payload with index %d", r);
  *buf = payloads[typePayload[contentType][r]];
  *size = payload_hdrs[typePayload[contentType][r]].length;
  *cap = typePayloadCap[contentType][r];
  return 1;
}








int get_payload (int contentType, int cap, char** buf, int* size) {
  int r;
  unsigned int i = 0;
  unsigned int cnt = 0;

  log_debug("get_payload: contentType = %d, initTypePayload = %d, typePayloadCount = %d",
      contentType, initTypePayload[contentType], typePayloadCount[contentType]);


  if (contentType <= 0 ||
      contentType >= MAX_CONTENT_TYPE ||
      initTypePayload[contentType] == 0 ||
      typePayloadCount[contentType] == 0)
    return 0;


  cnt = typePayloadCount[contentType];
   r = rand() % cnt;

  for (i=0; i < cnt; i++) {

    if (typePayloadCap[contentType][(r+i) % cnt] <= cap)
      continue;

    *buf = payloads[typePayload[contentType][(r+i)%cnt]];
    *size = payload_hdrs[typePayload[contentType][(r+i)%cnt]].length;
    return 1;
  }



  return 0;

}




int
find_content_length (char *hdr, int /*hlen*/) {
  char *clStart;
  char* clEnd;
  char *clValStart;
  int valLen;
  int contentLen;
  char buf[10];

  clStart = strstr(hdr, "Content-Length: ");
  if (clStart == NULL) {
    log_debug("Unable to find Content-Length in the header");
    return -1;
  }

  clEnd = strstr((char *)clStart, "\r\n");
  if (clEnd == NULL) {
    log_debug("Unable to find end of line for Content-Length");
    return -1;
  }

  // clValStart = clStart+strlen("Content-Length: ");
  clValStart = clStart+16;

  valLen = clEnd-clValStart;
  if (valLen > 9) return -1;
  memcpy(buf, clValStart, valLen);
  buf[valLen] = 0;
  contentLen = atoi(buf);
  return contentLen;
}






/*

void testOffset2Alnum_skipJSPattern () {
  char s1[] = "for (i=0; i<10; i++) { print i; }";

  char s2[] = "***abcde*****";
  int d, i;

  printf("s1 = %s\n", s1);
  printf("s2 = %s\n", s2);


  d = offset2Alnum_(s1, strlen(s1));
  printf ("offset2Alnum_ for s1 = %d\n", d);
  d = offset2Alnum_(s2, strlen(s2));
  printf ("offset2Alnum_ for s2 = %d\n", d);

  i = skipJSPattern (s1, strlen(s1));
  printf ("skipJSPattern for s1 = %d\n", i);
  i = skipJSPattern (s2, strlen(s2));
  printf ("skipJSPattern for s2 = %d\n", i);
}




void testOffset2Hex () {
  int d;
  char s3[] = "for (bc=0; bc<10; bc++) { ad=2*bc+ad; }";
  printf("len(s3)=%d; s3 = |%s|\n", (int)strlen(s3), s3);

  d = offset2Alnum_(s3, strlen(s3));
  printf ("offset2Alnum_ for s3 = %d\n", d);
  d = offset2Hex(s3, strlen(s3), 0);
  printf ("offset2Hex for s3 = %d\n", d);
}


void testCapacityJS () {
  int d;
  char s4[] = "\r\n\r\n abc = abc + 1;";
  char s6[] = "\r\n\r\n <script type=\"text/javascript\">abc = abc + 1;</script>";

  printf("\nTest for CONTENT_JAVASCRIPT:\n");
  printf("len(s4)=%d; s4 = |%s|\n", (int)strlen(s4), s4);

  d = offset2Alnum_(s4, strlen(s4));
  printf ("offset2Alnum_ for s4 = %d\n", d);
  d = offset2Hex(s4, strlen(s4), 0);
  printf ("offset2Hex for s4 = %d\n", d);

  printf("capacityJS  (JS) returns %d\n", capacityJS(s4, strlen(s4), CONTENT_JAVASCRIPT));
  printf("capacityJS3 (JS) returns %d\n", capacityJS3(s4, strlen(s4), CONTENT_JAVASCRIPT));

  printf("\nTest for CONTENT_HTML_JAVASCRIPT:\n");
  printf("len(s6)=%d; s6 = |%s|\n", (int)strlen(s6), s6);

  d = offset2Alnum_(s6, strlen(s6));
  printf ("offset2Alnum_ for s6 = %d\n", d);
  d = offset2Hex(s6, strlen(s6), 0);
  printf ("offset2Hex for s6 = %d\n", d);

  printf("capacityJS  (HTML) returns %d\n", capacityJS(s6, strlen(s6), CONTENT_HTML_JAVASCRIPT));
  printf("capacityJS3 (HTML) returns %d\n", capacityJS3(s6, strlen(s6), CONTENT_HTML_JAVASCRIPT));
}
*/


/*****
int main() {
  char buf[HTTP_MSG_BUF_SIZE];
  bzero(buf, sizeof(buf));
  // test for TYPE_HTTP_REQUEST
  // load_payloads("../../traces/client.out");
  // int len = find_client_payload(buf, 10000, TYPE_HTTP_REQUEST);
  // printf("%s\n", buf);

  // test for TYPE_HTTP_RESPONSE
  // load_payloads("../../traces/server-cnn-nogzip.out");
  // load_payloads("../../traces/server-portals.out"); // ptype==1?

  // testOffset2Alnum_skipJSPattern();
  // testOffset2Hex();
  // testCapacityJS();
  
  load_payloads("../../traces/server.out");
  // int r;
  // r = find_server_payload(&buf, sizeof(buf), TYPE_HTTP_RESPONSE, HTTP_CONTENT_JAVASCRIPT);
  // if (r > 0) {
  //   printf("Available payload capablity %d\n", r);
  // }
  // return r;

  return 0;
}
 *****/

