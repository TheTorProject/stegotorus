/** 
  The implmentation for non-abstract methods of FileStegMod Class

  AUTHORS: Vmon July 2013, Initial version
*/

#include <vector>
#include <algorithm>
#include <event2/buffer.h>
#include <assert.h>

#include <fstream> //for decode failure test

#include <math.h>

using namespace std;

#include "util.h"
#include "evbuf_util.h" //why do I need this now?
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
FileStegMod::FileStegMod(PayloadServer& payload_provider, double noise2signal_from_cfg, int child_type = -1)
  :_payload_server(payload_provider), noise2signal(noise2signal_from_cfg), c_content_type(child_type), outbuf(c_HTTP_PAYLOAD_BUF_SIZE)
{
  log_debug("max storage size: %lu >= maxs preceived storage: %lu >= max no of bits needed for storge %f", static_cast<unsigned long>(sizeof(message_size_t)),
            static_cast<unsigned long>(c_NO_BYTES_TO_STORE_MSG_SIZE), log2(c_MAX_MSG_BUF_SIZE)/8.0); //this is a clong vs gcc thing
            
  log_assert(sizeof(message_size_t) >= c_NO_BYTES_TO_STORE_MSG_SIZE);
  log_assert(c_NO_BYTES_TO_STORE_MSG_SIZE >= log2(c_MAX_MSG_BUF_SIZE)/8.0);

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
FileStegMod::extract_appropriate_respones_body(const std::vector<uint8_t>& payload_buf)
{
  //TODO: this need to be investigated, we might need two functions
  const static std::vector<uint8_t> end_of_header = {'\r', '\n', '\r', '\n'};
  auto hend = std::search(payload_buf.begin(), payload_buf.end(), end_of_header.begin(), end_of_header.end()); 
  if (hend == payload_buf.end()) {
    //log_debug("%s", payload_buf);
    log_debug("unable to find end of header in the HTTP template");
    return -1;
  }

  //hLen = hend+4-*payload_buf;
  return hend-payload_buf.begin()+end_of_header.size();

}

/**
   The overloaded version with evbuffer

   @param payload_buf can not be defined constant as evbuffer_search 
                      doesn't accept const.
*/
ssize_t 
FileStegMod::extract_appropriate_respones_body(evbuffer* payload_buf)
{
  //TODO: this need to be investigated, we might need two functions
  const evbuffer_ptr hend = evbuffer_search(payload_buf, end_of_header_indicator.c_str(), end_of_header_indicator.length() -1 , NULL);
  if (hend.pos == -1) {
    log_debug("unable to find end of header in the HTTP respose");
    return RESPONSE_INCOMPLETE;
  }

  return hend.pos + end_of_header_indicator.length();

}

/**
   Finds a payload of approperiate type and size and copy it into payload_buf
*/
const std::vector<uint8_t>& FileStegMod::pick_appropriate_cover_payload(size_t data_len, string& cover_id_hash)
{
  size_t max_capacity = _payload_server._payload_database.typed_maximum_capacity(c_content_type);

  if (max_capacity <= 0) {
    log_abort("SERVER ERROR: No payload of appropriate type=%d was found\n", (int) c_content_type);
    return PayloadServer::c_empty_payload;
  }

  if (data_len > (size_t) max_capacity) {
    log_abort("SERVER ERROR: type %d cannot accommodate data %d",
             (int) c_content_type, (int) data_len);
    return PayloadServer::c_empty_payload;
  }

  const vector<uint8_t>& payload_buf = _payload_server.get_payload(c_content_type, data_len, noise2signal, &cover_id_hash);
  if (payload_buf != PayloadServer::c_empty_payload) {
    log_debug("SERVER found the next HTTP response template with size %zu",
              payload_buf.size());
  } else { //we can't do much here anymore, we need to add payload to payload
    //database unless if the payload_server is serving randomly which means
    //next time probably won't serve a corrupted payload
    log_warn("SERVER couldn't find the next HTTP response template, enrich payload database and restart Stegotorus");
    return PayloadServer::c_empty_payload;
  }

  return payload_buf;
  
}

/**
   Find appropriate payload calls virtual embed to embed it appropriate
   to its type
   //TODO: also consolidate source buffer if it is scattered. That is why source
   //      can not be a const. this is violation
   // no side effect principal and this should be done explicitly somewhere else.
   // If the function needs  straighten buffer to transmit, then it should not 
   // accept a buffer but a memory block to begin with?

   @param source the data to be transmitted, 
   @param conn the connection over which the data is going to be transmitted

   @return the number of bytes transmitted
*/
int
FileStegMod::http_server_transmit(evbuffer *source, conn_t *conn)
{
  vector<uint8_t> data_to_be_transferred;
  int sbuflen = 0;

  ssize_t outbuflen = 0;
  ssize_t body_offset = 0;
  vector<uint8_t> newHdr;
  ssize_t newHdrLen = 0;
  size_t body_len = 0;
  size_t hLen = 0;

  evbuffer *dest;

  //call this from util to extract the buffer into memory block
  //data1 is allocated in evbuffer_to_memory_block we need to free
  //it at the end.
  sbuflen = evbuffer_to_memory_block(source, data_to_be_transferred);

  if (sbuflen < 0 /*&& c_content_type != HTTP_CONTENT_JAVASCRIPT || CONTENT_HTML_JAVASCRIPT*/) {
    log_warn("unable to extract the data from evbuffer");
    return -1;
  }

  //now we need to choose a payload. If a cover failed we through it out and try again
  string payload_id_hash;
  do  {
    
    const vector<uint8_t>& cover_payload = pick_appropriate_cover_payload(sbuflen, payload_id_hash);

    if (cover_payload == PayloadServer::c_empty_payload) {
      log_warn("Failed to aquire approperiate payload."); //if there is no approperiate cover of this type
      //then we can't continue :(
      return -1;
    }

    ssize_t cnt = cover_payload.size();

    //we shouldn't touch the cover as there is only one copy of it in the
    //the cache
    //log_debug("cover body: %s",cover_payload);
    body_offset =  extract_appropriate_respones_body(cover_payload);
    if (body_offset < 0) {
      log_warn("Failed to aquire approperiate payload.");
      _payload_server.disqualify_payload(payload_id_hash);
      continue; //we try with another cover
    }

    body_len = cnt-body_offset;
    hLen = body_offset;
    log_debug("coping body of %zu size", (body_len));
    if ((body_len) > c_HTTP_PAYLOAD_BUF_SIZE) {
      log_warn("HTTP response doesn't fit in the buffer %zu > %zu", (body_len)*sizeof(char), c_HTTP_PAYLOAD_BUF_SIZE);
      _payload_server.disqualify_payload(payload_id_hash);
      return -1;
    }
    outbuf.assign(cover_payload.begin() + body_offset, cover_payload.end());

    //int hLen = body_offset - (size_t)cover_payload - 4 + 1;
    //extrancting the body part of the payload
    log_debug("SERVER embeding transfer buffer with length %d into type %d", sbuflen, c_content_type);
    outbuflen = encode(data_to_be_transferred, outbuf);

    ///End of steg test!!
    if (outbuflen < 0) { //something went wrong in the emebeding we should
      //disqualify the cover and try another cover
      log_warn("SERVER embedding fails");
      _payload_server.disqualify_payload(payload_id_hash);
      
    } else { //we have successfully embeded the data in the cover
             //we can go ahead and prepare it to be sent as an
             //http respose
    
      //At this point body_len isn't valid anymore
      //we should only use outbuflen, cause the stegmodule might
      //have changed the original body_len

      //If everything seemed to be fine, if we are at the debug mode
      //We are going to test if we can decode the cover, just to be sure:
      if (!(LOG_SEV_DEBUG < log_get_min_severity())) { //only perform this during debug
        std::vector<uint8_t> recovered_data_for_test; //this is the size we have promised to decode func
        decode(outbuf, recovered_data_for_test);

        if ((data_to_be_transferred.size() != recovered_data_for_test.size()) ||
            (!std::equal(data_to_be_transferred.begin(), data_to_be_transferred.end(), recovered_data_for_test.begin()))) { //barf!!

          //keep the evidence for testing
          ofstream failure_evidence_file("fail_cover.log", ios::binary | ios::out);
          failure_evidence_file.write(reinterpret_cast<const char*>(cover_payload.data() + body_offset), body_len);
          failure_evidence_file.write(reinterpret_cast<const char*>(cover_payload.data() + body_offset), body_len);
          failure_evidence_file.close();

          ofstream failure_embed_evidence_file("failed_embeded_cover.log", ios::binary | ios::out);
          failure_embed_evidence_file.write(reinterpret_cast<const char*>(outbuf.data()), outbuflen);
          failure_embed_evidence_file.close();
          log_warn("decoding cannot recovers the encoded data consistantly for type %d", c_content_type);
          goto error;
        }
      } //end of cover test

      log_debug("SERVER FileSteg sends resp with hdr len %zu body len %zd",
                body_offset, outbuflen);

      //TODO: handle HTTP chunked transfer.
      //We need to check if set the header has a Content-length field

      log_assert(hLen < MAX_RESP_HDR_SIZE);
      vector<uint8_t> original_header(cover_payload.begin(), cover_payload.begin()+hLen);
      //now we update the header
      alter_length_in_response_header(original_header, outbuflen, newHdr);
      newHdrLen = newHdr.size();

      if (!newHdrLen) {
        log_warn("SERVER ERROR: failed to alter length field in response headerr");
        _payload_server.disqualify_payload(payload_id_hash);
        goto error;
      }

      //All is good. send it off
      dest = conn->outbound();
      if (evbuffer_add(dest, newHdr.data(), newHdrLen)) {
        log_warn("SERVER ERROR: evbuffer_add() fails for newHdr");
        goto error;
      }

      if (evbuffer_add(dest, outbuf.data(), outbuflen)) {
        log_warn("SERVER ERROR: evbuffer_add() fails for outbuf");
        goto error;
        return -1;
      }

      evbuffer_drain(source, sbuflen);
      return outbuflen;
    }

  } while(outbuflen < 0); //If we have failed reached this point it means that
  //we failed to embed, it is probably because the cover had problem,
  //we try again with different cover

 error:
  return -1;

}

int
FileStegMod::http_client_receive(conn_t *conn, struct evbuffer *dest,
                               struct evbuffer* source)
{
  unsigned int response_len = 0;
  int content_len = 0, outbuflen;
  uint8_t *httpHdr;

  outbuf.clear(); //make sure we start with an empty buffer but don't release the memory
  
  log_debug("Entering CLIENT receive");

  ssize_t body_offset = extract_appropriate_respones_body(source);
  if (body_offset == RESPONSE_INCOMPLETE) {
    log_debug("CLIENT Did not find end of HTTP header %d, Incomplete Response",
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

  if (response_len > evbuffer_get_length(source)) {
    log_debug("Incomplete response, waiting for more data.");
    return RECV_INCOMPLETE;
  }

  httpHdr = evbuffer_pullup(source, response_len);

  if (httpHdr == NULL) {
    log_warn("CLIENT unable to pullup the complete HTTP body");
    return RECV_BAD;
  }

  vector<uint8_t> httpBody(httpHdr + hdrLen, httpHdr + response_len);
  log_debug("CLIENT unwrapping data out of type %d payload", c_content_type);

  outbuflen = decode(httpBody, outbuf);
  if (outbuflen < 0) {
    log_warn("CLIENT ERROR: FileSteg fails\n");
    return RECV_BAD;
  }

  log_debug("CLIENT unwrapped data of length %d:", outbuflen);

  if (evbuffer_add(dest, outbuf.data(), outbuflen)) {
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

void
FileStegMod::alter_length_in_response_header(const std::vector<uint8_t>& original_header, ssize_t new_content_length, std::vector<uint8_t>& new_header)
{
  string new_content_length_str(std::to_string(new_content_length));
  vector<uint8_t>::const_iterator length_field_end;

  auto length_field_start = std::search(original_header.begin(), original_header.end(), length_field_name.begin(), length_field_name.end());
  if (length_field_start == original_header.end()) {
    log_warn("unable to find the Content-Length field, adding the field...");

    //TODO: this not the correct behavoir and can work as a descriminator.
    //we need to add decocding length from chunk the client side instead
    
    //we are addining it at the end
    length_field_end = original_header.end() - end_of_header_indicator.length();
    new_header.insert(new_header.end(), original_header.begin(), length_field_end);
    //insert an end of field
    new_header.insert(new_header.end(), end_of_field_indicator.begin(), end_of_field_indicator.end());
    //insert the content-length field
    new_header.insert(new_header.end(), length_field_name.begin(), length_field_name.end());

  } else {
  
    length_field_start += length_field_name.length();

    length_field_end = std::search(length_field_start, original_header.end(), end_of_field_indicator.begin(), end_of_field_indicator.end());
    if (length_field_end ==  original_header.end()) {
      log_warn("payload with bad header. unable to find the end of Content-Length field.");
      return;
    }
  
    //copy the first part of the header
    new_header.insert(new_header.end(), original_header.begin(), length_field_start);

  }

  //either way copy the new length after space
  new_header.push_back(' ');
  new_header.insert(new_header.end(), new_content_length_str.begin(), new_content_length_str.end());
  
  //copy the rest of the header
  new_header.insert(new_header.end(), length_field_end,  original_header.end());

}
 	

int
FileStegMod::find_content_length (char *hdr, int /*hlen*/) {
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

int FileStegMod::isGzipContent (char *msg) {
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
int FileStegMod::findContentType (char *msg) {
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
