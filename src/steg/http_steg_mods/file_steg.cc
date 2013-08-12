/** 
  The implmentation for non-abstract methods of FileStegMod Class

  AUTHORS: Vmon July 2013, Initial version
*/

#include <list>
#include <event2/buffer.h>
#include <assert.h>

using namespace std;

#include "util.h"
#include "../payload_server.h"

#include "file_steg.h"
#include "connections.h"
/**
  constructor, sets the playoad server

  @param the payload server that is going to be used to provide cover
         to this module.
*/
FileStegMod::FileStegMod(PayloadServer* payload_provider, double noise2signal_from_cfg, int child_type = -1)
  :_payload_server(payload_provider), noise2signal(noise2signal_from_cfg), c_content_type(child_type)
{
  

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
size_t 
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

  return (size_t)hend+4;

}

/**
   The overloaded version with evbuffer
*/
size_t 
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
ssize_t FileStegMod::pick_appropriate_cover_payload(size_t data_len, char** payload_buf)
{
  size_t max_capacity = _payload_server->_payload_database.typed_maximum_capacity(c_content_type);

  if (max_capacity <= 0) {
    log_warn("SERVER ERROR: No payload of approperiate type=%d was found\n", (int) c_content_type);
    return -1;
  }

  if (data_len > (size_t) max_capacity) {
    log_warn("SERVER ERROR: type %d cannot accommodate data %d",
             (int) c_content_type, (int) data_len);
    return -1;
  }

  ssize_t payload_size;
  if (_payload_server->get_payload(c_content_type, data_len, payload_buf,
                                   (int*)&payload_size, noise2signal) == 1) {
    log_debug("SERVER found the next HTTP response template with size %d",
              (int)payload_size);
  } else {
    log_warn("SERVER couldn't find the next HTTP response template");
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
  uint8_t outbuf[c_HTTP_MSG_BUF_SIZE];
  ssize_t outbuflen = 0;

  uint8_t newHdr[MAX_RESP_HDR_SIZE];
  ssize_t newHdrLen;

  if (sbuflen < 0) {
    log_warn("unable to extract the data from evbuffer");
    return -1;
  }

  //now we need to choose a payload
  char* cover_payload;
  size_t cnt = pick_appropriate_cover_payload(sbuflen, &cover_payload);

  //we shouldn't touch the cover as there is only one copy of it in the
  //the cache
  ssize_t body_offset =  extract_appropriate_respones_body(cover_payload, cnt);
  if (body_offset < 0)
    {
      log_warn("Failed to aquire approperiate payload.");
      return -1;
    }
  size_t hLen = body_offset - (size_t)cover_payload;
  memcpy(outbuf, (const void*)body_offset, (cnt-hLen)*sizeof(char));

  //int hLen = body_offset - (size_t)cover_payload - 4 + 1;
  //extracting the body part of the payload
  log_debug("SERVER embeding data1 with length %d into type %d", (int)cnt, c_content_type);
  outbuflen = encode(data1, sbuflen, outbuf, cnt - hLen);

  if (outbuflen < 0) {
    log_warn("SERVER embeding fails fails");
    return -1;
  }
  log_debug("SERVER FileSteg sends resp with hdr len %lu body len %lu",
            hLen, outbuflen);

  //TODO instead of generating the header we should just manipulate
  //it
  //The only possible problem is length but we are not changing 
  //the length for now
  /*int newHdrLen = gen_response_header((char*) "application/pdf", 0,
    outbuflen, (char*)newHdr, sizeof(newHdr));
  if (newHdrLen < 0) {
    log_warn("SERVER ERROR: gen_response_header fails for pdfSteg");
    return -1;
    }*/
  //I'm not crazy, these are filler for later change
  assert((size_t)outbuflen == cnt - hLen); //changing length is not supported yet
  memcpy(newHdr, cover_payload, hLen*sizeof(char)+4);
  newHdrLen = hLen;

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
  uint8_t outbuf[HTTP_MSG_BUF_SIZE];
  int content_len = 0, outbuflen;
  uint8_t *httpHdr, *httpBody;

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

  outbuflen = decode(httpBody, content_len, outbuf);
  if (outbuflen < 0) {
    log_warn("CLIENT ERROR: FileSteg fails\n");
    return RECV_BAD;
  }

  log_debug("CLIENT unwrapped data of length %d:", content_len);

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
