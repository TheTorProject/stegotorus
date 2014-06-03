/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#include "util.h"
#include "../payload_server.h"
#include "file_steg.h"
#include "swfSteg.h"
#include "compression.h"
#include "connections.h"


#include <event2/buffer.h>
#include <assert.h>

static const char http_response_1[] =
  "HTTP/1.1 200 OK\r\n"
  "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
  "Cache-Control: no-store\r\n"
  "Connection: close\r\n"
  "Content-Type: application/x-shockwave-flash\r\n"
  "Content-Length: ";

//unsigned int
//swf_wrap(PayloadServer* pl, char* inbuf, int in_len, char* outbuf, int out_sz) {
int SWFSteg::encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len) {
  char* tmp_buf;
  int out_swf_len;
  int in_swf_len;

  char* swf;
  char hdr[512];
  unsigned int hdr_len;

  char* tmp_buf2;
  char* resp;
  int resp_len;
  
  if (headless_capacity((char*)cover_payload, cover_len) <  (int) data_len) {
    log_warn("not enough cover capacity to embed data");
    return -1; //not enough capacity is an error because you should have check 
    //before requesting
  }

if (get_generated_payload(HTTP_CONTENT_SWF, -1, &resp, &resp_len)) {
	log_warn("swfsteg: no suitable payload found\n");
	return -1;
 }



swf = strstr(resp, "\r\n\r\n") + 4;

in_swf_len = resp_len - (swf - resp);

  tmp_buf = (char *)xmalloc(data_len + SWF_SAVE_HEADER_LEN + SWF_SAVE_FOOTER_LEN);
  tmp_buf2 = (char *)xmalloc(data_len + SWF_SAVE_HEADER_LEN + SWF_SAVE_FOOTER_LEN + 512);

  memcpy(tmp_buf, swf+8, SWF_SAVE_HEADER_LEN); //look at get_payload in trace_payload_server. 
  memcpy(tmp_buf+SWF_SAVE_HEADER_LEN, data, data_len);
  memcpy(tmp_buf+SWF_SAVE_HEADER_LEN+data_len, swf +in_swf_len-SWF_SAVE_FOOTER_LEN, SWF_SAVE_FOOTER_LEN);
  out_swf_len =
    compress((const uint8_t *)tmp_buf,
             SWF_SAVE_HEADER_LEN + data_len + SWF_SAVE_FOOTER_LEN,
             (uint8_t *)tmp_buf2+8,
             data_len + SWF_SAVE_HEADER_LEN + SWF_SAVE_FOOTER_LEN + 512-8,
             c_format_zlib);

  hdr_len =   gen_response_header((char*) "application/x-shockwave-flash", 0, out_swf_len + 8, hdr, sizeof(hdr));

  //  fprintf(stderr, "hdr = %s\n", hdr);
				       
  memcpy(tmp_buf2, cover_payload, 4);
  ((int*) (tmp_buf2))[1] = out_swf_len;
  
  memcpy(data, hdr, hdr_len);
  memcpy(data+hdr_len, tmp_buf2, out_swf_len + 8);

  free(tmp_buf);
  free(tmp_buf2);
  return out_swf_len + 8 + hdr_len;
}




ssize_t SWFSteg::decode(const uint8_t *cover_payload, size_t cover_len, uint8_t* data)
{
  int inf_len;
  size_t tmp_len = cover_len * 32; //asset later?
  char* tmp_buf = (char *)xmalloc(tmp_len);

  for (;;) {
    inf_len = decompress(cover_payload + 8, cover_len - 8,
                         (uint8_t *)tmp_buf, tmp_len);
    if (inf_len != -2)
      break;
    tmp_len *= 2;
    tmp_buf = (char *)xrealloc(tmp_buf, tmp_len);
  }

  if (inf_len < 0 ||
      sizeof(data) < c_HTTP_MSG_BUF_SIZE) {
    fprintf(stderr, "inf_len = %d\n", inf_len);
    free(tmp_buf);
    return -1;
  }

  memcpy(data, tmp_buf + SWF_SAVE_HEADER_LEN,
         inf_len - SWF_SAVE_HEADER_LEN - SWF_SAVE_FOOTER_LEN);
  
tmp_len= inf_len - SWF_SAVE_HEADER_LEN - SWF_SAVE_FOOTER_LEN; //reassigned to existing variable

return (ssize_t)tmp_len; //added for new return type
}

ssize_t SWFSteg::headless_capacity(char *cover_body, int body_length)
{
  return static_headless_capacity((char*)cover_body, body_length);
}

/**
compute the capcaity of the cover by getting a pointer to the
beginig of the body in the response

@param cover_body pointer to the begiing of the body
@param body_length the total length of message body
*/
unsigned int SWFSteg::static_headless_capacity(char *cover_body, int body_length)
{
  
 
  if (body_length <= 0)
     return 0;
  
  (void)cover_body; //to get around warning
  //int from = starting_point((uint8_t*)cover_body, (size_t)body_length);
  //if (from < 0) //invalid format
    //return 0;
    
  ssize_t hypothetical_capacity = ((ssize_t)body_length) - (SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 8 + 512);

  return max(hypothetical_capacity, (ssize_t)0);

}

ssize_t SWFSteg::capacity(const uint8_t *cover_payload, size_t len)
{
  return static_capacity((char*)cover_payload, len);
}

//Temp: should get rid of ASAP
unsigned int SWFSteg::static_capacity(char *cover_payload, int len)
{
  ssize_t body_offset = extract_appropriate_respones_body(cover_payload, len);
  if (body_offset == -1) //couldn't find the end of header
    return 0; //useless payload
 
   return static_headless_capacity(cover_payload + body_offset, len - body_offset);
}



SWFSteg::SWFSteg(PayloadServer* payload_provider, double noise2signal)
 :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_SWF, 1)

{

}
