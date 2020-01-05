/* Copyright 2012-2020 The Tor Project Inc.
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include <ctype.h>
#include <event2/buffer.h>
#include <iostream>

#include "util.h"
#include "../payload_server.h"
#include "file_steg.h"
#include "htmlSteg.h"
#include "compression.h"
#include "connections.h"

const std::string HTMLSteg::c_js_block_start_tag = "<script type=\"text/javascript\">";
const std::string HTMLSteg::c_js_block_end_tag = "</script>";

ssize_t
HTMLSteg::headless_capacity(const std::vector<uint8_t>& cover_body) {
  ssize_t cnt=0;

  // jump to the beginning of the body of the HTTP message
  auto cur_pos{cover_body.begin()};

  while ((cur_pos = std::search(cur_pos, cover_body.end(), c_js_block_start_tag.begin(), c_js_block_start_tag.end())) != cover_body.end()) {
    auto jsStart{cur_pos + c_js_block_start_tag.length()};
    auto jsEnd{std::search(jsStart, cover_body.end(), c_js_block_end_tag.begin(), c_js_block_end_tag.end())};
    if (jsEnd == cover_body.end()) break;

    // we have successfully found a block
    // count the number of usable hex char between jsStart+31 and jsEnd
    size_t chunk_len = jsEnd-jsStart;
    cnt += js_code_block_preliminary_capacity(jsStart, chunk_len);

    cur_pos = jsEnd + c_js_block_end_tag.length(); //This does not goes over end of cover_body
    //because we already has confirmed that it contains c_js_block_start_end_str QED
  }

  size_t actual_capacity = max(static_cast<ssize_t>(0), (cnt - JS_DELIMITER_SIZE)/2);  
  log_debug("html payload has capacity %lu", actual_capacity);
  return actual_capacity;

}

/**
   this function carry the only major part that is different between a
   js file and html file. As such html file will re-implement it accordingly
   As the result encode and decode function for both types remains the same.

   this is the overloaded version for htmlsteg variety where js code
   is scattered int th html file
*/
ssize_t
HTMLSteg::encode_http_body(const std::vector<uint8_t>& data, const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& cover_and_data)
{
  auto data_it = data.begin();
  auto cover_it = cover_payload.begin();
  auto cover_and_data_it = cover_and_data.begin();

  //Sanity check
  log_assert(cover_and_data.size() >= cover_payload.size());
  
  log_debug("at htmlsteg encode-http trying to encode %lu", data.size());

  unsigned int encCnt = 0;  // num of data encoded in jData
  int fin = 0;

  size_t original_dlen = data.size();

  while (encCnt < original_dlen) {
    auto jsStart = std::search(cover_it, cover_payload.end(), c_js_block_start_tag.begin(), c_js_block_start_tag.end());
    if (jsStart == cover_payload.end()) {
      log_warn("lack of usable JS; can't find startScriptType\n");
      return encCnt;
    }

    //jump copy everything in between up to the beginnig of the js block,
    //from original cover to the cover with data 
    auto skip = jsStart - cover_it + c_js_block_start_tag.length();
#ifdef DEBUG
    log_debug("copying %d (skip) char from jtp to jdp\n", skip);
#endif
    std::copy_n(cover_it, skip, cover_and_data_it);
    cover_and_data_it += skip;
    cover_it += skip;

    auto jsEnd{std::search(jsStart, cover_payload.end(), c_js_block_end_tag.begin(), c_js_block_end_tag.end())};
    if (jsEnd == cover_payload.end()) {
      log_warn("lack of usable JS; can't find %s\n", c_js_block_start_tag.c_str());
      return encCnt;
    }

    // we need the size of the block so we can jump the iterator
    //after being done with the block
    auto block_size = jsEnd - cover_it;

    // n = encode2(dp, jtp, jdp, dlen, jtlen, jdlen, &fin);
    auto number_of_bytes_encoded_in_current_block = encode_in_single_js_block(cover_it, jsEnd, data_it, data.end(), cover_and_data_it, fin);

    // update encCnt and other iterator
    encCnt += number_of_bytes_encoded_in_current_block;
    log_assert(encCnt <= original_dlen);
    data_it += number_of_bytes_encoded_in_current_block;

    cover_it += block_size;
    cover_and_data_it += block_size;
    
#ifdef DEBUG
      log_debug("%d bytes encoded", encCnt);
#endif      
    //copy the js end tag
    //because jsEnd is the result of matching c_js_block_start_tag length we are sure that we
    //we at least have cover equal to c_js_block_start_tag length left QED
    std::copy_n(jsEnd, c_js_block_end_tag.length(), cover_and_data_it);

    // update the iterators
    cover_and_data_it += c_js_block_end_tag.length();
    cover_it += c_js_block_end_tag.length();
  }

  //we are here because we consumed all data, otherwise it is a bug
  log_assert(encCnt == original_dlen);
  //if we have fin == 0 it is
  //the follownig case:
  // handling the boundary case in which JS_DELIMITER hasn't been
  // added by encode()
  if (fin == 0 && encCnt == original_dlen) { //this means that we consumed all data but we were not able to
    //to stick in the DELIMINATOR because we ran out of space in our block so
    //we can just stick it in current byte as long as we have still some cover
    //left.
    if (cover_it < cover_payload.end()) {
      *cover_and_data_it = JS_DELIMITER;
      cover_it++;
      cover_and_data_it++;
    } else {
      log_debug("not enough room for the JS_DELIMITER so we do not need it");
    }

  }

  //now that we have encoded all the data then we can copy
  //the rest of the cover even beyond the block.
  std::copy(cover_it, cover_payload.end(), cover_and_data_it);

  log_debug("%d bytes encoded", encCnt);

  return encCnt;
  
}

ssize_t
HTMLSteg::decode_http_body(const std::vector<uint8_t>& cover_and_data, std::vector<uint8_t>& data, int& fin)
{
  int decCnt = 0;
  auto cover_it = cover_and_data.begin();

  fin = 0;
  while (fin == 0) {
    auto jsStart = std::search(cover_it, cover_and_data.end(), c_js_block_start_tag.begin(), c_js_block_start_tag.end());
    if (jsStart == cover_and_data.end()) {
      log_warn("Can't find startScriptType for decoding data inside script type JS\n");
      return decCnt;
    }

    cover_it = jsStart + c_js_block_start_tag.length();

    auto jsEnd{std::search(jsStart, cover_and_data.end(), c_js_block_end_tag.begin(), c_js_block_end_tag.end())};

    if (jsEnd == cover_and_data.end()) {
      log_warn("Can't find endScriptType for decoding data inside script type JS\n");
      return decCnt;
    }

    // the JS for decoding data is between jsStart and jsEnd
    auto number_of_bytes_decoded_in_current_block = decode_single_js_block(cover_it, jsEnd, data, fin);
    if (number_of_bytes_decoded_in_current_block > 0) {
      decCnt += number_of_bytes_decoded_in_current_block;
    }
    
    cover_it = jsEnd + c_js_block_end_tag.length();
  } // while (*fin==0)

  return decCnt;

}

/**
   constructor to steup the correct hard-coded type
 */
HTMLSteg::HTMLSteg(PayloadServer& payload_provider, double noise2signal)
  :JSSteg(payload_provider, noise2signal, HTTP_CONTENT_HTML)
{
  //adding extensions this module support
  vector<string> supported_extension_list({"html", "htm", "shtml", "php"});
  extensions = supported_extension_list;
  
}
