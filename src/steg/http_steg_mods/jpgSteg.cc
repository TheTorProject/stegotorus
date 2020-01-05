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


int JPGSteg::corrupt_reset_interval(uint8_t* raw_data, int len)
{
	int i;
	int counter = 0;
	for (i = 0; i < len-1; i++) {
		if (raw_data[i] == FRAME && raw_data[i+1] == FRAME_RST) {
			short *ri = (short *) (raw_data+i + 2);
			*ri = 0xFFFF;
			counter++;
		}
	}
	return counter;

}

int JPGSteg::starting_point(const std::vector<uint8_t>& raw_data)
{
	int lm = 0; // Last Marker
	for (size_t i = 0; i < raw_data.size()-1; i++) {
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
 
	const unsigned short flen = raw_data[lm+2]*256 + raw_data[lm+2+1]; // Frame length in big endian and + 2 for FFDA, and skip the header
	log_debug("Size of the last DA frame: %hu at %06X\n", flen, lm);

    ssize_t start_point = lm + 2 + flen;
    if (start_point > (signed)(raw_data.size() - 2 - c_NO_BYTES_TO_STORE_MSG_SIZE)) start_point = -1;

	return start_point; 

}

/**
   compute the capcaity of the cover by getting a pointer to the
   beginig of the body in the response

   @param cover_body pointer to the begiing of the body
   @param body_length the total length of message body
 */
ssize_t JPGSteg::headless_capacity(const std::vector<uint8_t>& cover_body)
{  
  if (cover_body.size() == 0)
    return 0;

  int from = starting_point(cover_body);
  if (from < 0) //invalid format 
    return 0;
    
  ssize_t hypothetical_capacity = ((ssize_t)cover_body.size()) - from - 2 - (ssize_t)c_NO_BYTES_TO_STORE_MSG_SIZE; // 2 for FFD9, 4 for len

  return max(hypothetical_capacity, (ssize_t)0); 

}

ssize_t JPGSteg::encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payload)
{
  assert(data.size() < c_MAX_MSG_BUF_SIZE);
  if (headless_capacity(cover_payload) <  (int) data.size()) {
    log_warn("not enough cover capacity to embed data");
    return -1; //not enough capacity is an error because you should have check 
    //before requesting
  }

  int from = starting_point(cover_payload);
  if (from < 0) {
    log_warn("corrupted jpg payload");
    return -1;
  }

  log_debug("embeding %zu at %i of jpeg cover size %zu", data.size(),from, cover_payload.size());

  ssize_t data_len = data.size();
  vector<uint8_t> encoded_data_len = le_encode(data_len);

  //Sanity check
  log_assert(encoded_data_len.size() == c_NO_BYTES_TO_STORE_MSG_SIZE);

  //embeding the encoded length
  std::copy(encoded_data_len.begin(), encoded_data_len.end(), cover_payload.begin()+from);
  
  //Sanity check in case capacity function is insane
  log_assert(data_len < static_cast<ssize_t>(cover_payload.size() - (from + c_NO_BYTES_TO_STORE_MSG_SIZE)));
  
  std::copy(data.begin(), data.end(), cover_payload.begin()+from+c_NO_BYTES_TO_STORE_MSG_SIZE);

  return cover_payload.size();
    
}

ssize_t JPGSteg::decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data)
{
	// TODO: There may be FFDA in the data
    ssize_t from = starting_point(cover_payload);
    if (from < 0) {
      log_warn("invalid jpg payload, corrupted?");
      return -1;
    }

    vector<uint8_t> encoded_data_len(cover_payload.data()+from,  cover_payload.data()+from + c_NO_BYTES_TO_STORE_MSG_SIZE);

    size_t s = static_cast<size_t>(le_decode(encoded_data_len));

    //We assume the enough mem is allocated for the data
    log_debug("recovering %zu from %zd of cover size %zu", s, from, cover_payload.size());

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
    //adding extensions this module support only if the type is JS (not being called by HTML CONST)
  vector<string> supported_extension_list({"jpg", "jpeg"});
  extensions = supported_extension_list;

}
