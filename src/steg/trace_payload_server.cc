#include "util.h"
#include "trace_payload_server.h"

TracePayloadServer::TracePayloadServer(MachineSide init_side, string fname)
  : PayloadServer(init_side)
{

  load_payloads(fname.c_str());

  init_JS_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, JS_MIN_AVAIL_SIZE);
  _payload_database.type_detail[HTTP_CONTENT_JAVASCRIPT] =  TypeDetail(pl.max_JS_capacity, pl.typePayloadCount[HTTP_CONTENT_JAVASCRIPT]);

  init_HTML_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, HTML_MIN_AVAIL_SIZE);
  _payload_database.type_detail[HTTP_CONTENT_HTML] =  TypeDetail(pl.max_HTML_capacity, pl.typePayloadCount[HTTP_CONTENT_PDF]);

  init_PDF_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, PDF_MIN_AVAIL_SIZE);

  _payload_database.type_detail[HTTP_CONTENT_PDF] =  TypeDetail(pl.max_PDF_capacity, pl.typePayloadCount[HTTP_CONTENT_PDF]);

  init_SWF_payload_pool(HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, 0);

  _payload_database.type_detail[HTTP_CONTENT_SWF] = TypeDetail(0, pl.typePayloadCount[HTTP_CONTENT_SWF]);

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
  char* msgbuf;
  int cap;
  int mode;

  if (pl.payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?\n");
    return 0;
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_JAVASCRIPT);
    if (mode == CONTENT_JAVASCRIPT) {

      cap = capacityJS3(msgbuf, p->length, mode);
      if (cap <  JS_DELIMITER_SIZE)
	continue;

      cap = (cap - JS_DELIMITER_SIZE)/2;

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
  char* msgbuf;
  int cap;
  int mode;



  if (pl.payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?\n");
    return 0;
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_HTML);
    if (mode == CONTENT_HTML_JAVASCRIPT) {
      
      cap = capacityJS3(msgbuf, p->length, mode);
      if (cap <  JS_DELIMITER_SIZE) 
	continue;

      cap = (cap - JS_DELIMITER_SIZE)/2;

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
      cap = capacityPDF(msgbuf, p->length);
      if (cap > minCapacity) {
	log_debug("pdf (index %d) greater than mincapacity %d", cnt, minCapacity);
	pl.typePayloadCap[contentType][cnt] = (cap-PDF_DELIMITER_SIZE)/2;
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
TracePayloadServer::init_SWF_payload_pool(int len, int type, int /*unused */)
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


int TracePayloadServer::get_payload (int contentType, int cap, char** buf, int* size) {
  int r, i, cnt, found = 0, numCandidate = 0, first, best, current;

  log_debug("contentType = %d, initTypePayload = %d, typePayloadCount = %d",
            contentType, pl.initTypePayload[contentType],
            pl.typePayloadCount[contentType]);

  if (contentType <= 0 ||
      contentType >= MAX_CONTENT_TYPE ||
      pl.initTypePayload[contentType] == 0 ||
      pl.typePayloadCount[contentType] == 0)
    return 0;


  cnt = pl.typePayloadCount[contentType];
  r = rand() % cnt;
  best = r;
  first = r;

  i = -1;
  // we look at MAX_CANDIDATE_PAYLOADS payloads that have enough capacity
  // and select the best fit
  while (i < (cnt-1) && numCandidate < MAX_CANDIDATE_PAYLOADS) {
    i++;
    current = (r+i)%cnt;

    if (pl.typePayloadCap[contentType][current] <= cap)
      continue;

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
    *buf = pl.payloads[pl.typePayload[contentType][best]];
    *size = pl.payload_hdrs[pl.typePayload[contentType][best]].length;
    return 1;
  } else {
    return 0;
  }
}


void TracePayloadServer::load_payloads(const char* fname)
{
  FILE* f;
  char buf[HTTP_MSG_BUF_SIZE];
  char buf2[HTTP_MSG_BUF_SIZE];
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
      pl.payloads[pl.payload_count] = (char *)xmalloc(pentry.length + 1);
      memcpy(pl.payloads[pl.payload_count], buf, pentry.length);
    } else {
      pentry.length = r;
      pl.payloads[pl.payload_count] = (char *)xmalloc(pentry.length + 1);
      memcpy(pl.payloads[pl.payload_count], buf2, pentry.length);
    }
    pl.payload_hdrs[pl.payload_count] = pentry;
    pl.payloads[pl.payload_count][pentry.length] = 0;
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
      inbuf = pl.payloads[r];
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

