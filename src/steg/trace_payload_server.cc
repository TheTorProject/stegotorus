#include "util.h"

#include "payload_server.h"
#include "trace_payload_server.h"
#include "file_steg.h"
// // #include "http_steg_mods/swfSteg.h"
// // #include "http_steg_mods/pdfSteg.h"
#include "http_steg_mods/jsSteg.h"
#include "http_steg_mods/htmlSteg.h"

#include "protocol/chop_blk.h" //We need this to know what's the minimum block size

TracePayloadServer::TracePayloadServer(MachineSide init_side, string fname)
  : PayloadServer(init_side), c_max_buffer_size(1000000)
{

  load_payloads(fname.c_str());

  init_JS_payload_pool(HTTP_PAYLOAD_BUF_SIZE, TYPE_HTTP_RESPONSE, chop_blk::MIN_BLOCK_SIZE);
  _payload_database.type_detail[HTTP_CONTENT_JAVASCRIPT] =  TypeDetail(pl.max_JS_capacity, pl.typePayloadCount[HTTP_CONTENT_JAVASCRIPT]);

  init_HTML_payload_pool(HTTP_PAYLOAD_BUF_SIZE, TYPE_HTTP_RESPONSE, HTML_MIN_AVAIL_SIZE);
  _payload_database.type_detail[HTTP_CONTENT_HTML] =  TypeDetail(pl.max_HTML_capacity, pl.typePayloadCount[HTTP_CONTENT_HTML]);

  //Disabling PDF and SWF till they get migrated to new vector model
  //init_PDF_payload_pool(HTTP_PAYLOAD_BUF_SIZE, TYPE_HTTP_RESPONSE, PDF_MIN_AVAIL_SIZE); //should we continue to use PDF_MIN_AVAIL_SIZE?

  //_payload_database.type_detail[HTTP_CONTENT_PDF] =  TypeDetail(pl.max_PDF_capacity, pl.typePayloadCount[HTTP_CONTENT_PDF]); //deprecating use of pl.max_PDF_capacity ASAP

  //init_SWF_payload_pool(HTTP_PAYLOAD_BUF_SIZE, TYPE_HTTP_RESPONSE, 0);

  //_payload_database.type_detail[HTTP_CONTENT_SWF] = TypeDetail(c_MAX_MSG_BUF_SIZE, pl.typePayloadCount[HTTP_CONTENT_SWF]);

  //DONE (for SWF?): Add FileTypeSteg Capability to trace server
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

int TracePayloadServer::init_JS_payload_pool(int len, int type, int minCapacity) {
  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0;
  int sumPayloadSize = 0;
  int minPayloadCap = 0, maxPayloadCap = 0;
  int sumPayloadCap = 0;

  unsigned int contentType = HTTP_CONTENT_JAVASCRIPT;

  int cnt = 0;
  int r;
  pentry_header* p;
  int cap;
  int mode;

  if (pl.payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?\n");
    return 0;
  }

  DummyPayloadServer dummy_payload_server;
  JSSteg jssteg_capacity_computer_engine(dummy_payload_server);

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    vector<uint8_t> msgbuf(pl.payloads[r].begin(), pl.payloads[r].end());

    mode = has_eligible_HTTP_content(reinterpret_cast<char*>(msgbuf.data()), p->length, HTTP_CONTENT_JAVASCRIPT);
    if (mode == CONTENT_JAVASCRIPT) {
      cap = jssteg_capacity_computer_engine.capacity(msgbuf);
      if (cap == 0)
        continue;

      if (cap > minCapacity) {
        pl.typePayloadCap[contentType][cnt] = cap; // (cap-JS_DELIMITER_SIZE)/2;
        // because we use 2 hex char to encode every data byte, the available
        // capacity for encoding data is divided by 2
        pl.typePayload[contentType][cnt] = r;
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

  pl.max_JS_capacity = maxPayloadCap;
  pl.initTypePayload[contentType] = 1;
  pl.typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, pl.typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  log_debug("minPayloadCap  = %d", minPayloadCap); 
  log_debug("maxPayloadCap  = %d", maxPayloadCap); 
  log_debug("avgPayloadCap  = %f", (float)sumPayloadCap/(float)cnt); 
  return 1;
}

int  TracePayloadServer::init_HTML_payload_pool(int len, int type, int minCapacity) {

  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0; 
  int sumPayloadSize = 0;
  int minPayloadCap = 0, maxPayloadCap = 0;
  int sumPayloadCap = 0;

  unsigned int contentType = HTTP_CONTENT_HTML;

  int cnt = 0;
  int r;
  pentry_header* p;
  int cap;
  int mode;

  if (pl.payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?\n");
    return 0;
  }

  DummyPayloadServer dummy_payload_server;
  HTMLSteg htmlsteg_capacity_computer_engine(dummy_payload_server);


  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    vector<uint8_t> msgbuf(pl.payloads[r].begin(), pl.payloads[r].end());

    mode = has_eligible_HTTP_content(reinterpret_cast<char*>(msgbuf.data()), p->length, HTTP_CONTENT_HTML);
    if (mode == CONTENT_HTML_JAVASCRIPT) {
      cap = htmlsteg_capacity_computer_engine.capacity(msgbuf);

      if (cap == 0)
        continue;

      if (cap > minCapacity) {
        pl.typePayloadCap[contentType][cnt] = cap; // (cap-JS_DELIMITER_SIZE)/2;
        // because we use 2 hex char to encode every data byte, the available
        // capacity for encoding data is divided by 2
        pl.typePayload[contentType][cnt] = r;
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

  pl.max_HTML_capacity = maxPayloadCap;
  pl.initTypePayload[contentType] = 1;
  pl.typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, pl.typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  log_debug("minPayloadCap  = %d", minPayloadCap); 
  log_debug("maxPayloadCap  = %d", maxPayloadCap); 
  log_debug("avgPayloadCap  = %f", (float)sumPayloadCap/(float)cnt); 
  return 1;
}

/* Temperory commenting out stuff related to
    PDF and SWF covers till we 
 * move their class to new model
int
TracePayloadServer::init_PDF_payload_pool(int len, int type, int minCapacity)
{

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
  

  if (pl.payload_count == 0) {
     fprintf(stderr, "payload_count == 0; forgot to run load_payloads()?\n");
     return 0;
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_PDF);
    if (mode > 0) {
      // use capacityPDF() to find out the amount of data that we
      // can encode in the pdf doc 
      // cap = minCapacity+1;
      cap = PDFSteg::static_capacity(msgbuf, p->length);
      if (cap > minCapacity) { //why checking this
        //log_debug("pdf (index %d) has capacity %d greater than mincapacity %d", cnt, cap, minCapacity);
        cap = (cap-PDF_DELIMITER_SIZE)/2;
        pl.typePayloadCap[contentType][cnt] = cap;
        pl.typePayload[contentType][cnt] = r;
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

  pl.max_PDF_capacity = maxPayloadCap;
  pl.initTypePayload[contentType] = 1;
  pl.typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
            contentType, pl.typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  log_debug("minPayloadCap  = %d", minPayloadCap); 
  log_debug("maxPayloadCap  = %d", maxPayloadCap); 
  log_debug("avgPayloadCap  = %f", (float)sumPayloadCap/(float)cnt); 
  return 1;
}

int
TracePayloadServer::init_SWF_payload_pool(int len, int type, int )
{
  // stat for usable payload
  int minPayloadSize = 0, maxPayloadSize = 0; 
  int sumPayloadSize = 0;

  int cnt = 0;
  int r;
  pentry_header* p;
  char* msgbuf;
  int mode;
  unsigned int contentType = HTTP_CONTENT_SWF;


  if (pl.payload_count == 0) {
     fprintf(stderr, "payload_count == 0; forgot to run load_payloads()?\n");
     return 0;
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];
    // found a payload corr to the specified contentType

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_SWF);
    if (mode > 0) {
      pl.typePayload[contentType][cnt] = r;
      pl.typePayloadCap[contentType][cnt] = c_MAX_MSG_BUF_SIZE;
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
    
  pl.initTypePayload[contentType] = 1;
  pl.typePayloadCount[contentType] = cnt;
  log_debug("init_payload_pool: typePayloadCount for contentType %d = %d",
     contentType, pl.typePayloadCount[contentType]); 
  log_debug("minPayloadSize = %d", minPayloadSize); 
  log_debug("maxPayloadSize = %d", maxPayloadSize); 
  log_debug("avgPayloadSize = %f", (float)sumPayloadSize/(float)cnt); 
  return 1;
}

*/
const std::vector<uint8_t>&
TracePayloadServer::get_payload (int contentType, int cap, double noise2signal, string* payload_id_hash) {
  int r, i, cnt, found = 0, numCandidate = 0, first, best, current;

  (void) payload_id_hash; //TracePayloadServer doesn't support disqualification
    if(cap <0) {
	log_warn("swfsteg: calling this one\n");
     }

  log_debug("contentType = %d, initTypePayload = %d, typePayloadCount = %d",
            contentType, pl.initTypePayload[contentType],
            pl.typePayloadCount[contentType]);

  if ((!is_activated_valid_content_type(contentType)) ||
      pl.initTypePayload[contentType] == 0 ||
      pl.typePayloadCount[contentType] == 0
      ) {
    //|| (cap <= 0) //why should you ask for no or negative capacity?
    //Aparently negative capacity means your cap doesn't matter
    //I'll stuff as much as I can in it. This is in the case of
    //swf format.
    return PayloadServer::c_empty_payload;
  }

  cnt = pl.typePayloadCount[contentType];
  r = rand() % cnt;
  best = r;
  first = r;

  i = -1;
  // we look at MAX_CANDIDATE_PAYLOADS payloads that have enough capacity
  // and select the best fit, we'll loop once
  while (i < (cnt-1) && numCandidate < MAX_CANDIDATE_PAYLOADS) {
    i++;
    current = (r+i)%cnt; //vmon:This is not a random choice of candidates!

    //If the cap <= 0 is asked then we are not responsible for the consequence
    if (cap > 0)
      if (pl.typePayloadCap[contentType][current] <= cap || pl.payload_hdrs[pl.typePayload[contentType][current]].length/(double)cap < noise2signal) {
        //log_debug("payload %d only offer %d bytes \n", current, pl.typePayloadCap[contentType][current]);
        continue;
      }
    //log_debug("payload capacity %d vs requested %d", pl.typePayloadCap[contentType][current], cap);
    if (found) {
      if (pl.payload_hdrs[pl.typePayload[contentType][best]].length >
          pl.payload_hdrs[pl.typePayload[contentType][current]].length)
        best = current;
    } else {
      first = current;
      best = current;
      found = 1;
    }
    numCandidate++;
  }

  if (found) {
    log_debug("first payload size=%d, best payload size=%d, num candidate=%d\n",
      pl.payload_hdrs[pl.typePayload[contentType][first]].length,
      pl.payload_hdrs[pl.typePayload[contentType][best]].length,
      numCandidate);
    return pl.payloads[pl.typePayload[contentType][best]];
  } else {
    log_warn("couldn't find payload with desired capacity: r=%d, checked %d payloads\n", r, i);
    return PayloadServer::c_empty_payload;
  }

}

void TracePayloadServer::load_payloads(const char* fname)
{
  FILE* f;
  vector<uint8_t> buf(HTTP_PAYLOAD_BUF_SIZE, 0);
  vector<uint8_t>buf2(HTTP_PAYLOAD_BUF_SIZE, 0);
  pentry_header pentry;
  int pentryLen;
  int r;

  srand(time(NULL));
  f = fopen(fname, "r");
  if (f == NULL) {
    fprintf(stderr, "Cannot open trace file %s. Exiting\n", fname);
    exit(1);
  }

  memset(pl.payload_hdrs, 0, sizeof(pl.payload_hdrs));
  pl.payload_count = 0;

  while (pl.payload_count < MAX_PAYLOADS) {

    if (fread(&pentry, 1, sizeof(pentry_header), f) < sizeof(pentry_header)) {
      break;
    }
   
    pentryLen = ntohl(pentry.length);
    if((unsigned int) pentryLen > HTTP_PAYLOAD_BUF_SIZE) {
#ifdef DEBUG
      fprintf(stderr, "pentry too big %d\n", pentryLen);
#endif
      // skip to the next pentry
      if (fseek(f, pentryLen, SEEK_CUR)) {
        fprintf(stderr, "skipping to next pentry fails\n");
      }
      continue;
    }

    pentry.length = pentryLen;
    pentry.ptype = ntohs(pentry.ptype);

    if (fread(buf.data(), 1, pentry.length, f) < (unsigned int) pentry.length)
      break;

    // todo:
    // fixed content length for gzip'd HTTP msg
    // fixContentLen returns -1, if no change to the msg
    // otherwise, it put the new HTTP msg (with hdr changed) in buf2
    // and returns the size of the new msg

    r = -1;
    if (pentry.ptype == TYPE_HTTP_RESPONSE) {
      r = fixContentLen (reinterpret_cast<char*>(buf.data()), pentry.length, reinterpret_cast<char*>(buf2.data()), HTTP_PAYLOAD_BUF_SIZE);
    }

    if (r < 0) {
      pl.payloads[pl.payload_count].assign(buf.begin(), buf.begin()+pentry.length);
    } else {
      pentry.length = r;
      pl.payloads[pl.payload_count].assign(buf2.begin(), buf2.begin()+pentry.length);
    }
    pl.payload_hdrs[pl.payload_count] = pentry;
    pl.payloads[pl.payload_count].push_back(0);
    pl.payload_count++;
  } // while


  log_debug("loaded %d payloads from %s\n", pl.payload_count, fname);

  fclose(f);
}

unsigned int TracePayloadServer::find_client_payload(char* buf, int len, int type) {
  int r = rand() % pl.payload_count;
  int cnt = 0;
  char* inbuf;

  log_debug("trying payload %d", r);
  while (1) {
    pentry_header* p = &pl.payload_hdrs[r];
    if (p->ptype == type) {
      inbuf = reinterpret_cast<char*>(pl.payloads[r].data());
      int requested_uri_type = find_uri_type(inbuf, p->length);
      //we also need to check if the user has restricted the type,
      //empty active type list means no restriciton
      if (!is_activated_valid_content_type(requested_uri_type)) {
        log_debug("type %d of payload %d is not activated trying next payload", requested_uri_type, r);
        goto next;
      }

      log_debug("found payload %d of actived type %d", r, requested_uri_type);
      
      if (p->length > len) {
        fprintf(stderr, "BUFFER TOO SMALL... \n");
        goto next;
      }
      else
        len = p->length;
      break;
    }
  next:
    r = (r+1) % pl.payload_count;

    // no matching payloads...
    if (cnt++ == pl.payload_count) {
      log_warn("no matching payloads");
      return 0;
    }
  }

  inbuf[len] = 0;

  // clean up the buffer...
  return parse_client_headers(inbuf, buf, len);
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
int
TracePayloadServer::fixContentLen (char* payload, int payloadLen, char *buf, int bufLen) {

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

int 
TracePayloadServer::has_eligible_HTTP_content (char* buf, int len, int type) {
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
  
  //check if we need to update this for current SWF implementation
  if (type == HTTP_CONTENT_SWF && swfFlag == 1 && 
      ((len + buf - end) > SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 8))
    return 1;

  return 0;
}

