/**
   Copyright 2013 Tor Inc
   
   Steg Module to encode/decode data into png images
   AUTHOR:
   - Vmon: Initial version, July 2013

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
using namespace std;

#include <event2/buffer.h>

#include "util.h"
#include "connections.h"
#include "../payload_server.h"

#include "file_steg.h"
#include "pngSteg.h"

ssize_t
PNGSteg::headless_capacity(const std::vector<uint8_t>& cover_body)
{
  if (cover_body.size() <= 0 || cover_body.size() <= PNGSteg::c_magic_header_length)
    return 0;

  size_t total_capacity = 0;

  vector<uint8_t>::const_iterator search_starting_point = cover_body.begin() + PNGSteg::c_magic_header_length;
  PNGChunkData cur_data_chunk(search_starting_point, cover_body.end()), next_data_chunk;
  if (cur_data_chunk.invalid_file_format) //corrupted or invalid format
    return 0;
  total_capacity = cur_data_chunk.length;
  while(cur_data_chunk.get_next_IDAT_chunk(next_data_chunk)) {
      total_capacity += next_data_chunk.length;
      cur_data_chunk = next_data_chunk;
  }

  return (total_capacity <= c_NO_BYTES_TO_STORE_MSG_SIZE) ? 0 : total_capacity - c_NO_BYTES_TO_STORE_MSG_SIZE; //counting for the data length
}

ssize_t PNGSteg::encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payload)
{
  if (cover_payload.size() > c_MAX_MSG_BUF_SIZE) {
    log_warn("Too much data to be fit into recovering buffer during the decode process");
    return -1;
  }
    
  //Make a new block of data with data length attached
  ssize_t data_len = data.size();
  vector<uint8_t> encoded_data_len = le_encode(data_len);

  //Sanity check
  log_assert(encoded_data_len.size() == c_NO_BYTES_TO_STORE_MSG_SIZE);

  vector<uint8_t> lengthed_data(c_NO_BYTES_TO_STORE_MSG_SIZE + data_len);

  //embeding the encoded length and the rest of the data
  std::copy(encoded_data_len.begin(), encoded_data_len.end(), lengthed_data.begin());
  std::copy(data.begin(), data.end(), lengthed_data.begin() + c_NO_BYTES_TO_STORE_MSG_SIZE);

  auto end_of_data = lengthed_data.end();
  auto cur_data_offset = lengthed_data.begin();
  PNGChunkData next_data_chunk(cover_payload.begin() + c_magic_header_length, cover_payload.end());

  if (next_data_chunk.invalid_file_format)
    return -1;
  
  PNGChunkData cur_data_chunk = next_data_chunk;
  std::vector<uint8_t>::iterator mutable_chunk_offset = cover_payload.begin();

  do {
    cur_data_chunk = next_data_chunk;
    size_t length_to_embed = min(cur_data_chunk.length, (size_t) (end_of_data - cur_data_offset));
    //cur_data_chunk.chunk_offset is a const iterator
    std::advance(mutable_chunk_offset, std::distance<std::vector<uint8_t>::const_iterator>(cover_payload.begin(), cur_data_chunk.chunk_offset));
    std::copy_n(cur_data_offset, length_to_embed, mutable_chunk_offset + PNGChunkData::c_chunk_header_length); 
    cur_data_offset += length_to_embed;

    cur_data_chunk.get_next_IDAT_chunk(next_data_chunk);

  }while((cur_data_offset < end_of_data) && (!cur_data_chunk.invalid_file_format));

  if ((cur_data_offset < end_of_data)) {
    log_warn("Ran out of space while fiting the data into PNG cover");
    return -1;
  }

  return cover_payload.size();

}

ssize_t PNGSteg::decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data)
{
  //The assumption is that the data buffer can cantain the maximum size of the 
  //data
  //Make a new block of data with data length attached
  PNGChunkData  next_data_chunk(cover_payload.begin() + c_magic_header_length, cover_payload.end());
  PNGChunkData  cur_data_chunk = next_data_chunk;

  //recovering data length
  size_t data_recovered_length = 0;
  vector<uint8_t> encoded_data_len;
  size_t header_recovering_length;

  if (next_data_chunk.invalid_file_format)
    return -1;

  //recovering the length of the data in case it is stored across multiple chunks
  do {
    cur_data_chunk = next_data_chunk;
    header_recovering_length = min(cur_data_chunk.length, c_NO_BYTES_TO_STORE_MSG_SIZE - data_recovered_length);
    encoded_data_len.insert(encoded_data_len.end(), cur_data_chunk.chunk_offset+PNGChunkData::c_chunk_header_length, cur_data_chunk.chunk_offset+PNGChunkData::c_chunk_header_length + header_recovering_length);
    data_recovered_length += header_recovering_length;

  }while(data_recovered_length < c_NO_BYTES_TO_STORE_MSG_SIZE && cur_data_chunk.get_next_IDAT_chunk(next_data_chunk));

  if (data_recovered_length < c_NO_BYTES_TO_STORE_MSG_SIZE) {
    log_warn("Ran out of PNG cover before reocovering the data length, something is wrong :'(, probably corrupted cover");
    return -1;
  }
  
  size_t data_length = static_cast<size_t>(le_decode(encoded_data_len));

  //now we know the exact length 
  if (data_length > c_MAX_MSG_BUF_SIZE) {
    log_warn("Data buffer too small to contains decoded data with length %u", (unsigned int) data_length);
    return -1;
  }

  //If the last chunk had any residue let's put them in data buffer
  size_t valid_data_in_chunk = min(cur_data_chunk.length-header_recovering_length, (size_t)data_length);
  auto data_start = cur_data_chunk.chunk_offset + PNGChunkData::c_chunk_header_length + header_recovering_length;
  data.insert(data.end(), data_start, data_start + valid_data_in_chunk);
  data_recovered_length += valid_data_in_chunk;

  //copy the rest of the data
  while(data_recovered_length < data_length + c_NO_BYTES_TO_STORE_MSG_SIZE) {
    if (!cur_data_chunk.get_next_IDAT_chunk(next_data_chunk)) {
      log_warn("Ran out of PNG cover before reocovering the whole data, something is wrong :'(, probably corrupted cover");
      return -1;
    }
    cur_data_chunk = next_data_chunk;
    valid_data_in_chunk = min(cur_data_chunk.length, data_length - data_recovered_length);
    auto data_start = cur_data_chunk.chunk_offset + PNGChunkData::c_chunk_header_length;
    data.insert(data.end(), data_start, data_start + valid_data_in_chunk);
    data_recovered_length += valid_data_in_chunk;
  }

  return data.size();

}
   
/**
   constructor just to call parent constructor
*/
PNGSteg::PNGSteg(PayloadServer& payload_provider, double noise2signal)
  :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_PNG)
{
    //adding extensions this module support only if the type is JS (not being called by HTML CONST)
  vector<string> supported_extension_list({"png"});
  extensions = supported_extension_list;

}
