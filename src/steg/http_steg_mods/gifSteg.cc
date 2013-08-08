#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <assert.h>

#include "util.h"
#include "connections.h"
#include "../payload_server.h"

#include "file_steg.h"
#include "gifSteg.h"

/**
  finds the 0x21 code in the file which is the begining of the image 
  block and then write the data till the end not overwriting the 0x3B
  ending code.

  @param cover_payload the gif file 
  @param cover_len     the size of the cover

  @return the start of the image block after sentinel where information can
          be stored -1 if no block found
*/
ssize_t GIFSteg::starting_point(const uint8_t *raw_data, size_t len)
{
	for (size_t i = 0; i < len-1; i++) {
		if (raw_data[i] == c_image_block_sentinel)
          return i+1;
    }
    log_warn("Couldn't find the starting of the image block");

    return -1;
}

ssize_t GIFSteg::capacity(const uint8_t *raw, size_t len)
{
  return static_capacity((char*)raw, len);
}

//Temp: should get rid of ASAP
unsigned int GIFSteg::static_capacity(char *cover_payload, int len)
{
  ssize_t body_offset = extract_appropriate_respones_body(cover_payload, len);
  if (body_offset == -1) //couldn't find the end of header
    return 0;  //useless payload
 
  size_t header_length = body_offset - (size_t)cover_payload;

  int from = starting_point((uint8_t*)body_offset, len - header_length);
  return min(len - header_length - from - 1 - sizeof(size_t), (size_t)0); // 1 for 0x3B, 4 for len
}


int GIFSteg::encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len)
{
	int from = starting_point(cover_payload, cover_len);
	memcpy(cover_payload+from, &data_len, sizeof(data_len));
	memcpy(cover_payload+from+sizeof(data_len), data, data_len);
	return 0;
}

ssize_t GIFSteg::decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data)
{
	// TODO: There may be FFDA in the data
    ssize_t from = starting_point(cover_payload, cover_len);
    assert(from >= 0);
    size_t s = (size_t)*(cover_payload+from);

    assert(s < c_HTTP_MSG_BUF_SIZE);
    //We assume that enough data is allocated data here cause it is when we know the data size
	memcpy(data, cover_payload+from+sizeof(int), s);
	return s;

}

/**
   constructor just to call parent constructor
*/
GIFSteg::GIFSteg(PayloadServer* payload_provider, double noise2signal)
  :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_GIF)
{
}
