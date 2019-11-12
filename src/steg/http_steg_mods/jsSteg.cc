#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <assert.h>

#include "util.h"
#include "connections.h"
#include "../payload_server.h"

#include "file_steg.h"
#include "jpgSteg.h"

int JPGSteg::starting_point(const vector<uint8_t>& raw_data, int len)
{
	int i;
	int lm = 0; // Last Marker
	//long lf; // Last Frame
	for (i = 0; i < len-1; i++) {
		if (raw_data[i] == FRAME && raw_data[i+1] == FRAME_SCAN) {
			lm = i;
			LOG("0xFFDA at %06X\n", i)
              break;
		} else if (raw_data[i] == FRAME && raw_data[i+1] == FRAME_RST) {
			LOG("0xFFDD at %06X\n", i)
		} else if (raw_data[i] == FRAME && raw_data[i+1] == FRAME_RST0) {
			LOG("0xFFD0 at %06X\n", i)
		}
	}

    if (lm == 0) {
      //couldn't find any marker probably corrupted file
      log_warn("couldn't find the last marker in jpg payload, corrupted payload probably");
      return -1;
    }
 
	const unsigned short *flen = (const unsigned short *)(raw_data.data()+lm+2); // Frame length
	unsigned short swapped = SWAP(*flen);
	log_debug("Size of the last DA frame: %hu at %06X\n", swapped, lm);

    ssize_t start_point = lm + 2 + swapped;
    if (start_point > (signed)(len - 2 - c_NO_BYTES_TO_STORE_MSG_SIZE)) start_point = -1;
	return start_point; // *flen; // 2 for FFDA, and skip the header

}

<<<<<<< variant A
ssize_t JPGSteg::headless_capacity(char *cover_body, int body_length)
{
  return static_headless_capacity((char*)cover_body, body_length);
}

>>>>>>> variant B
======= end
/**
   compute the capcaity of the cover by getting a pointer to the
   beginig of the body in the response

   @param cover_body pointer to the begiing of the body
   @param body_length the total length of message body
 */
unsigned int JPGSteg::headless_capacity(const std::vector<uint8_t>& cover_body)
{  
  if (body_length <= 0)
    return 0;

  int from = starting_point((uint8_t*)cover_body, static_cast<size_t>(body_length));
  if (from < 0) //invalid format 
    return 0;
    
  ssize_t hypothetical_capacity = ((ssize_t)body_length) - from - 2 - (ssize_t)c_NO_BYTES_TO_STORE_MSG_SIZE;

  return max(hypothetical_capacity, (ssize_t)0); // 2 for FFD9, 4 for len

}

ssize_t JPGSteg::encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payload)
{
  assert(data.size() < c_MAX_MSG_BUF_SIZE);
  if (headless_capacity((uint8_t*)cover_payload, cover_payload.size()) <  (int) data.size()) {
    log_warn("not enough cover capacity to embed data");
    return -1; //not enough capacity is an error because you should have check 
    //before requesting
  }

  int from = starting_point(cover_payload, cover_len);
  if (from < 0) {
    log_warn("corrupted jpg payload");
    return -1;
  }

  log_debug("embeding %lu at %i of cover size %lu", data.size(),from, cover_payload.size());

  ssize_t data_len = data.size();
  memcpy(cover_payload.begin()+from, reinterpret_cast<uint8_t*>(&data_len), c_NO_BYTES_TO_STORE_MSG_SIZE); //only works for little-endian
  cover_payload.insert(cover_payload.begin()+from+c_NO_BYTES_TO_STORE_MSG_SIZE, data.begin(), data.end());
  return cover_payload.size();
    
}

ssize_t JPGSteg::decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data)
{
	// TODO: There may be FFDA in the data
    ssize_t from = starting_point(cover_payload, cover_len);
    if (from < 0) {
      log_warn("invalid jpg payload, corrupted?");
      return -1;
    }
      
    size_t s = *(reinterpret_cast<const message_size_t*>(cover_payload.data()+from));
    s %= c_HIGH_BYTES_DISCARDER;
    if (s > c_MAX_MSG_BUF_SIZE) {
      log_warn("too much embeded data, corrupted?");
      return -1;
    }

    //We assume the enough mem is allocated for the data
    log_debug("recovering %zu from %zd of cover size %zu", s, from, cover_len);

    auto data_start = cover_payload.begin()+from+c_NO_BYTES_TO_STORE_MSG_SIZE;
	data.insert(data.begin(), data_start, data_start+s);
	return s;

}

/**
   constructor just to call parent constructor
*/
JPGSteg::JPGSteg(PayloadServer& payload_provider, double noise2signal)
  :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_JPEG)
{
}
