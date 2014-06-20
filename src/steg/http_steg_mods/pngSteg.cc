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

ssize_t PNGSteg::capacity(const uint8_t *raw, size_t len)
{
  return static_capacity((char*)raw, len);
}

ssize_t PNGSteg::headless_capacity(char *cover_body, int body_length)
{
  return static_headless_capacity((char*)cover_body, body_length);
}

/**
   compute the capcaity of the cover by getting a pointer to the
   beginig of the body in the response

   @param cover_body pointer to the begiing of the body
   @param body_length the total length of message body
 */
unsigned int PNGSteg::static_headless_capacity(char *cover_body, int body_length)
{
  if (body_length <= 0)
    return 0;

  size_t total_capacity = 0;

  PNGChunkData cur_data_chunk((uint8_t*)cover_body + c_magic_header_length, (uint8_t*)cover_body + body_length), next_data_chunk;
  if (not cur_data_chunk.chunk_offset) //corrupted or invalid format
    return 0;
  total_capacity = cur_data_chunk.length;
  while(cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)) {
      total_capacity += next_data_chunk.length;
      cur_data_chunk = next_data_chunk;
  }

  return (total_capacity <= sizeof(uint32_t)) ? 0 : total_capacity - sizeof(uint32_t); //counting for the data length
}

//Temp: should get rid of ASAP
unsigned int PNGSteg::static_capacity(char *cover_payload, int cover_length)
{
  ssize_t body_offset = extract_appropriate_respones_body(cover_payload, cover_length);
  if (body_offset == -1) //coulodn't find the end of header
    return 0;  //useless payload

  return static_headless_capacity(cover_payload + body_offset, cover_length - body_offset);

}

int PNGSteg::encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len)
{

  if (data_len > c_MAX_MSG_BUF_SIZE) {
    log_warn("To much data to be fit into recovering buffer during the decode process");
    return -1;
  }
    
  //Make a new block of data with data length attached
  uint8_t lengthed_data[data_len + sizeof(uint32_t)]; //This is in stack I hope
  uint32_t data_len_encode = (uint32_t)data_len;
  memcpy(lengthed_data, &data_len_encode, sizeof(uint32_t));
  memcpy(lengthed_data+sizeof(uint32_t), data, data_len * sizeof(uint8_t));

  uint8_t* end_of_data = lengthed_data + data_len + sizeof(uint32_t);
  uint8_t* cur_data_offset = lengthed_data;
  PNGChunkData next_data_chunk(cover_payload + c_magic_header_length, cover_payload + cover_len), cur_data_chunk;

  do {
    cur_data_chunk = next_data_chunk;
    size_t length_to_embed = min(cur_data_chunk.length, (size_t) (end_of_data - cur_data_offset));
    memcpy(cur_data_chunk.chunk_offset+ PNGChunkData::c_chunk_header_length, cur_data_offset, length_to_embed); 
    cur_data_offset += length_to_embed;

  }while((cur_data_offset < end_of_data) && (cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)));

  if ((cur_data_offset < end_of_data)) {
    log_warn("Ran out of space while fiting the data into PNG cover");
    return -1;
  }

  return cover_len;

}

ssize_t PNGSteg::decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data)
{
  //The assumption is that the data buffer can cantain the maximum size of the 
  //data
  //Make a new block of data with data length attached
  PNGChunkData  next_data_chunk((uint8_t*)cover_payload + c_magic_header_length, (uint8_t*)cover_payload + cover_len),cur_data_chunk;

  //recovering data length
  size_t data_recovered_length = 0;
  uint32_t data_length;
  size_t header_recovering_length;
  do {
    cur_data_chunk = next_data_chunk;
    header_recovering_length = min(cur_data_chunk.length, sizeof(uint32_t) - data_recovered_length);
    memcpy((void*)((&data_length) + data_recovered_length), cur_data_chunk.chunk_offset+PNGChunkData::c_chunk_header_length, header_recovering_length);
    data_recovered_length += header_recovering_length;

  }while(data_recovered_length < sizeof(uint32_t) && (cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)));

  if (data_recovered_length < sizeof(uint32_t)) {
    log_warn("Ran out of PNG cover before reocovering the whole data, something is wrong :'(, probably corrupted cover");
    return -1;
  }
  //now we know the exact length 
  if (data_length > c_MAX_MSG_BUF_SIZE) {
    log_warn("Data buffer too small to contains decoded data with length %u", (unsigned int) data_length);
    return -1;
  }

  //If the last chunk had any residue let's put them in data buffer
  size_t valid_data_in_chunk = min(cur_data_chunk.length-header_recovering_length, (size_t)data_length);
  memcpy(data, cur_data_chunk.chunk_offset + PNGChunkData::c_chunk_header_length + header_recovering_length, valid_data_in_chunk);
  data_recovered_length += valid_data_in_chunk;

  //moving stuff
  //memcpy(data, data + sizeof(uint32_t), data_recovered_length);
  //you can't move stuff like that :(
  
  while(data_recovered_length < data_length + sizeof(uint32_t)) {
    if (!cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)) {
      log_warn("Ran out of PNG cover before reocovering the whole data, something is wrong :'(, probably corrupted cover");
      return -1;
    }
    cur_data_chunk = next_data_chunk;
    valid_data_in_chunk = min(cur_data_chunk.length, data_length - data_recovered_length);
    memcpy(data + data_recovered_length, cur_data_chunk.chunk_offset + PNGChunkData::c_chunk_header_length, valid_data_in_chunk);
    data_recovered_length += valid_data_in_chunk;
  }

  return (ssize_t)data_length;

}
   
//   ur_data_chunk = next_data_chunk;
//     memcpy(cur_data_chunk.offset+8, cur_data_offset, cur_data_chunk.length);
//     cur_data_offset += cur_data_chunk.length;

//   }

//   uint8_t lengthed_data = char[data_len + sizeof(data_len)];
//   memcpy(lengthed_data, data_len, sizeof(data_len));
//   memcpy(lengthed_data+sizeof(data_len), data, data_len * sizeof(uint8_t));

//   uint8_t* end_of_data = lengthed_data + data_len + sizeof(data_len)
//   uint8_t* cur_data_offset = lengthed_data;

// }

/**
   constructor just to call parent constructor
*/
PNGSteg::PNGSteg(PayloadServer* payload_provider, double noise2signal)
  :FileStegMod(payload_provider, noise2signal, HTTP_CONTENT_PNG)
{
}
