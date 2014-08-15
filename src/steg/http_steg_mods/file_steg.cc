/** 
  The implmentation for non-abstract methods of FileStegMod Class

  AUTHORS: Vmon July 2013, Initial version
*/

#include <list>
#include <event2/buffer.h>
#include <assert.h>

#include <fstream> //for decode failure test

using namespace std;

#include "util.h"
#include "../payload_server.h"
//#include "jsSteg.h"

#include "file_steg.h"
#include "connections.h"

// error codes
#define INVALID_BUF_SIZE  -1
#define INVALID_DATA_CHAR -2

// controlling content gzipping for jsSteg
#define JS_GZIP_RESP             1

/**
  constructor, sets the playoad server

  @param the payload server that is going to be used to provide cover
         to this module.
*/
FileStegMod::FileStegMod(PayloadServer* payload_provider, double noise2signal_from_cfg, int child_type = -1)
  :_payload_server(payload_provider), noise2signal(noise2signal_from_cfg), c_content_type(child_type), outbuf(new uint8_t[c_HTTP_MSG_BUF_SIZE])
{
  assert(outbuf);

}

/** 
    Destructor, just releases the http buffer 
*/
FileStegMod::~FileStegMod()
{
  delete outbuf;
}



/**
   Encapsulate the repetative task of checking for the respones of content_type
   choosing one with appropriate size and extracting the body from header

   @param data_len: the length of data being embed should be < capacity
   @param payload_buf: the http response (header+body) corresponding going to cover the data
   @param payload_size: the size of the payload_buf

   @return the offset of the body content of payload_buf or < 0 in case of
           error, that is RESPONSE_INCOMPLETE (<0) if it is incomplete (can't
           find the start of body) or RESPONSE_BAD (<0) in case of other
           errors
*/


ssize_t 
FileStegMod::extract_appropriate_respones_body(char* payload_buf, size_t payload_size)
{
  (void) payload_size;
  //TODO: this need to be investigated, we might need two functions
  const char* hend = strstr(payload_buf, "\r\n\r\n");
  if (hend == NULL) {
    log_warn("unable to find end of header in the HTTP template");
    return -1;
  }

  //hLen = hend+4-*payload_buf;

  return hend-payload_buf+4;

}

/**
   The overloaded version with evbuffer
*/
ssize_t 
FileStegMod::extract_appropriate_respones_body(evbuffer* payload_buf)
{
  //TODO: this need to be investigated, we might need two functions
  evbuffer_ptr hend = evbuffer_search(payload_buf, "\r\n\r\n", sizeof ("\r\n\r\n") -1 , NULL);
  if (hend.pos == -1) {
    log_warn("unable to find end of header in the HTTP template");
    return -1;
  }

  return hend.pos + strlen("\r\n\r\n");

}

/**
   Finds a payload of approperiate type and size

   @param data_len: the payload should be able to accomodate this length
   @param payload_buf: the buff that is going to contain the chosen payloa

   @return payload size or < 0 in case of error
*/
ssize_t FileStegMod::pick_appropriate_cover_payload(size_t data_len, char** payload_buf, string& cover_id_hash)
{
  size_t max_capacity = _payload_server->_payload_database.typed_maximum_capacity(c_content_type);

  if (max_capacity <= 0) {
    log_abort("SERVER ERROR: No payload of appropriate type=%d was found\n", (int) c_content_type);
    return -1;
  }

  if (data_len > (size_t) max_capacity) {
    log_abort("SERVER ERROR: type %d cannot accommodate data %d",
             (int) c_content_type, (int) data_len);
    return -1;
  }

  ssize_t payload_size = 0;
  if (_payload_server->get_payload(c_content_type, data_len, payload_buf,
                                   (int*)&payload_size, noise2signal, &cover_id_hash) == 1) {
    log_debug("SERVER found the next HTTP response template with size %d",
              (int)payload_size);
  } else { //we can't do much here anymore, we need to add payload to payload
    //database unless if the payload_server is serving randomly which means
    //next time probably won't serve a corrupted payload
    log_warn("SERVER couldn't find the next HTTP response template, enrich payload database and restart Stegotorus");
    return -1;
  }

  return payload_size;

}

/**
   Find appropriate payload calls virtual embed to embed it appropriate
   to its type

   @param source the data to be transmitted
   @param conn the connection over which the data is going to be transmitted

   @return the number of bytes transmitted
*/
int
FileStegMod::http_server_transmit(evbuffer *source, conn_t *conn)
{

  uint8_t* data1;
  //call this from util to find to extract the buffer into memory block
  int sbuflen = evbuffer_to_memory_block(source, &data1);

  ssize_t outbuflen = 0;
  ssize_t body_offset = 0;
  uint8_t newHdr[MAX_RESP_HDR_SIZE];
  ssize_t newHdrLen = 0;
  size_t cnt = 0;
  size_t body_len = 0;
  size_t hLen = 0;

  if (sbuflen < 0) {
    log_warn("unable to extract the data from evbuffer");
    return -1;
  }
  
  if (c_content_type == HTTP_CONTENT_JAVASCRIPT) {
  //cnt = 0;
  //(size_t) sbuflen = evbuffer_get_length(source);
  //unsigned int datalen = 0;
  //char data[(int) sbuflen*2];
  
  //might have to move these outside if block?
  int gzipMode = JS_GZIP_RESP;

  struct evbuffer_iovec *iv;
  int nv, r;
  nv = evbuffer_peek(source, sbuflen, NULL, NULL, 0);
  iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);

  if (evbuffer_peek(source, sbuflen, NULL, iv, nv) != nv) {
    free(iv);
    return -1;
  }
  for (i = 0; i < nv; i++) {
    const unsigned char *p = (const unsigned char *)iv[i].iov_base;
    const unsigned char *limit = p + iv[i].iov_len;
    char c;

    while (p < limit && cnt < sbuflen) {
      c = *p++;
      data1[datalen] = "0123456789abcdef"[(c & 0xF0) >> 4];
      data1[datalen+1] = "0123456789abcdef"[(c & 0x0F) >> 0];
      datalen += 2;
      cnt++;
    }
  }

  free(iv);
}

  //now we need to choose a payload
  char* cover_payload;
  string payload_id_hash;

  cnt = pick_appropriate_cover_payload(sbuflen, &cover_payload, payload_id_hash);
  
  //we shouldn't touch the cover as there is only one copy of it in the
  //the cache
  body_offset =  extract_appropriate_respones_body(cover_payload, cnt);
  if (body_offset < 0) {
    log_warn("Failed to aquire approperiate payload.");
    _payload_server->disqualify_payload(payload_id_hash);
    return -1;
  }

  body_len = cnt-body_offset;
  hLen = body_offset;
  log_debug("coping body of %lu size", (body_len));
  if ((body_len) > c_HTTP_MSG_BUF_SIZE) {
    log_warn("HTTP response doesn't fit in the buffer %lu > %lu", (body_len)*sizeof(char), c_HTTP_MSG_BUF_SIZE);
    _payload_server->disqualify_payload(payload_id_hash);
    return -1;
  }
  memcpy(outbuf, (const void*)(cover_payload + body_offset), (body_len)*sizeof(char));

  //int hLen = body_offset - (size_t)cover_payload - 4 + 1;
  //extracting the body part of the payload
  log_debug("SERVER embeding data1 with length %d into type %d", sbuflen, c_content_type);
  outbuflen = encode(data1, sbuflen, outbuf, body_len);

  ///End of steg test!!
  if (outbuflen < 0) {
    log_warn("SERVER embedding fails");
    _payload_server->disqualify_payload(payload_id_hash);
    return -1;
  }


  //At this point body_len isn't valid anymore
  //we should only use outbuflen, cause the stegmodule might
  //have changed the original body_len

  //If everything seemed to be fine, New steg module test:
  if (!(LOG_SEV_DEBUG < log_get_min_severity())) { //only perform this during debug
    uint8_t recovered_data_for_test[sbuflen];
    decode(outbuf, outbuflen, recovered_data_for_test);

    if (memcmp(data1, recovered_data_for_test, sbuflen)) { //barf!!
      //keep the evidence for testing
     // if(pgenflag == FILE_PAYLOAD)
     //{
      	ofstream failure_evidence_file("fail_cover.log", ios::binary | ios::out);
      	failure_evidence_file.write(cover_payload + body_offset, body_len);
      	failure_evidence_file.write(cover_payload + body_offset, body_len);
      	failure_evidence_file.close();
     //}
      ofstream failure_embed_evidence_file("failed_embeded_cover.log", ios::binary | ios::out);
      failure_embed_evidence_file.write((const char*)outbuf, outbuflen);
      failure_embed_evidence_file.close();
      log_warn("decoding cannot recovers the encoded data consistantly for type %d", c_content_type);
      return -1;
    }
  }


  log_debug("SERVER FileSteg sends resp with hdr len %lu body len %lu",
            body_offset, outbuflen);


 
  //Update: we can't assert this anymore, SWFSteg changes the size
  //so this equalit.ie doesn't hold anymore
  //assert((size_t)outbuflen == body_len); //changing length is not supported yet
  //instead we need to check if SWF or PDF, the payload length is changed
  //and in that case we need to update the header
  
	/*if( c_content_type == HTTP_CONTENT_PDF) {
	  //TODO instead of generating the header we should just manipulate
  //it
  //The only possible problem is length but we are not changing 
  //the length for now
  newHdrLen = gen_response_header((char*) "application/pdf", 0,
    outbuflen, (char*)newHdr, sizeof(newHdr));
  if (newHdrLen < 0) {
    log_warn("SERVER ERROR: gen_response_header fails for pdfSteg");
    return -1;
    }
   }*/
  //I'm not crazy, these are filler for later change

   if ((size_t)outbuflen == body_len) { 
    memcpy(newHdr, cover_payload,hLen);
    newHdrLen = hLen;
	
  }
  else { //if the length is different, then we need to update the header
    newHdrLen = alter_length_in_response_header((uint8_t *)cover_payload, hLen, outbuflen, newHdr);
    if (!newHdrLen) {
      log_warn("SERVER ERROR: failed to alter length field in response headerr");
      _payload_server->disqualify_payload(payload_id_hash);
      return -1;
    }
  }

  evbuffer *dest = conn->outbound();
  if (evbuffer_add(dest, newHdr, newHdrLen)) {
    log_warn("SERVER ERROR: evbuffer_add() fails for newHdr");
    return -1;
    }

  if (evbuffer_add(dest, outbuf, cnt)) {
    log_warn("SERVER ERROR: evbuffer_add() fails for outbuf");
    return -1;
  }

  evbuffer_drain(source, sbuflen);
  return outbuflen;

}

int
FileStegMod::http_client_receive(conn_t *conn, struct evbuffer *dest,
                               struct evbuffer* source)
{
  unsigned int response_len = 0;
  uint8_t* outbuf;
  int content_len = 0, outbuflen;
  uint8_t *httpHdr, *httpBody;

  
  

  int decCnt, i, j, k, buf2len;
  ev_ssize_t r;
  struct evbuffer * scratch; //maybe move to filesteg class?
  char c;

  log_debug("Entering CLIENT receive");

  ssize_t body_offset = extract_appropriate_respones_body(source);
  if (body_offset == RESPONSE_INCOMPLETE) {
    log_warn("CLIENT Did not find end of HTTP header %d, Incomplete Response",
             (int) evbuffer_get_length(source));
    return RECV_INCOMPLETE;
  }

  log_debug("CLIENT received response header with len %d", (int)body_offset-4);

  response_len = 0;
  ssize_t hdrLen = body_offset;
  response_len += hdrLen;

  httpHdr = evbuffer_pullup(source, hdrLen);
  if (httpHdr == NULL) {
    log_warn("CLIENT unable to pullup the complete HTTP header");
    return RECV_BAD;
  }

  content_len = find_content_length((char*)httpHdr, hdrLen);
  if (content_len < 0) {
    log_warn("CLIENT unable to find content length");
    return RECV_BAD;
  }
  log_debug("CLIENT received Content-Length = %d\n", content_len);

  response_len += content_len;

  if (response_len > evbuffer_get_length(source))
    return RECV_INCOMPLETE;

  httpHdr = evbuffer_pullup(source, response_len);

  if (httpHdr == NULL) {
    log_warn("CLIENT unable to pullup the complete HTTP body");
    return RECV_BAD;
  }

  httpBody = httpHdr + hdrLen;
  log_debug("CLIENT unwrapping data out of type %d payload", c_content_type);

  outbuf = new uint8_t[c_HTTP_MSG_BUF_SIZE];
  outbuflen = decode(httpBody, content_len, outbuf);
  if (outbuflen < 0) {
    log_warn("CLIENT ERROR: FileSteg fails\n");
    delete[] outbuf;
    return RECV_BAD;
  }

  log_debug("CLIENT unwrapped data of length %d:", outbuflen);

  if( c_content_type == HTTP_CONTENT_JAVASCRIPT ) {
  /*if (outbuflen % 2) {
    log_debug("CLIENT ERROR: An odd number of hex characters received\n");
    return RECV_BAD;
  }

  if (! isxString(outbuf)) {
    log_debug("CLIENT ERROR: Data received not hex");
    return RECV_BAD;
  }*/

  // log_debug("Hex data received:");
  //    buf_dump ((unsigned char*)data, decCnt, stderr);

  // get a scratch buffer
  scratch = evbuffer_new();
  if (!scratch) return RECV_BAD;

  if (evbuffer_expand(scratch, outbuflen/2)) {
    log_warn("CLIENT ERROR: Evbuffer expand failed \n");
    evbuffer_free(scratch);
    return RECV_BAD;
  }

  // convert hex data back to binary
  for (i=0, j=0; i< outbuflen; i=i+2, ++j) {
    sscanf(&outbuf[i], "%2x", (unsigned int*) &k);
    c = (char)k;
    evbuffer_add(scratch, &c, 1);
  }

  if (evbuffer_add_buffer(dest, scratch)) {
    evbuffer_free(scratch);
    log_warn("CLIENT ERROR: Failed to transfer buffer");
    return RECV_BAD;
  }
  log_debug("Added scratch (buffer) to dest\n");

  evbuffer_free(scratch);


  if (response_len <= (int) evbuffer_get_length(source)) {
    if (evbuffer_drain(source, response_len) == -1) {
      log_warn("CLIENT ERROR: Failed to drain source");
      return RECV_BAD;
    }
  }
  else {
    log_warn("response_len > buffer size... can't drain");
    exit(-1);
  }


  log_debug("Drained source for %d char\n", response_len);

  //  downcast_steg(s)->have_received = 1;
}

  else {
  if (evbuffer_add(dest, outbuf, outbuflen)) {
    log_warn("CLIENT ERROR: evbuffer_add to dest fails\n");
    delete[] outbuf;
    return RECV_BAD;
  }
  delete[] outbuf; //done with outbuf anyway

  if (evbuffer_drain(source, response_len) == -1) {
    log_warn("CLIENT ERROR: failed to drain source\n");
    return RECV_BAD;
  }
   
  }

  conn->expect_close();
  return RECV_GOOD;

}

size_t FileStegMod::alter_length_in_response_header(uint8_t* original_header, size_t original_header_length, ssize_t new_content_length, uint8_t new_header[])
{

  char * length_field_start = strstr(reinterpret_cast<char *>(original_header), "Content-Length:");
  if (length_field_start == NULL)
    return 0;
  
  length_field_start +=  + strlen("Content-Length:");

  char * length_field_end = strstr(reinterpret_cast<char *>(length_field_start), "\r\n");
  if (length_field_end == NULL)
    return 0;

  memcpy(new_header, original_header, ((uint8_t*)length_field_start - original_header));
  new_header+= ((uint8_t*)length_field_start - original_header);
  sprintf(reinterpret_cast<char *>(new_header), " %ld", new_content_length);
  size_t length_of_content_length = strlen(reinterpret_cast<const char *>(new_header));
  new_header += length_of_content_length;
  memcpy(new_header, length_field_end,  (original_header_length - ((uint8_t*)length_field_end - original_header)));

  return original_header_length -  (length_field_end - length_field_start) + length_of_content_length; 
  

}
