/**
   Copyright 2013 Tor Inc
   
   Steg Module to encode/decode data into png images
   AUTHOR:
   - Vmon: Initial version, July 2013

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

//Temp: should get rid of ASAP
unsigned int PNGSteg::static_capacity(char *cover_payload, int cover_length)
{
  
  size_t total_capacity = 0;
  PNGChunkData cur_data_chunk((uint8_t*)cover_payload + c_magic_header_length, (uint8_t*)cover_payload + (size_t)cover_length), next_data_chunk;
  while(cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)) {
      total_capacity += next_data_chunk.length;
      cur_data_chunk = next_data_chunk;
  }

  return (total_capacity > 4) ? 0 : total_capacity - 4; //counting for the data length
}

int PNGSteg::encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len)
{
  //Make a new block of data with data length attached
  uint8_t lengthed_data[data_len + sizeof(data_len)]; //This is in stack I hope
  memcpy(lengthed_data, &data_len, sizeof(data_len));
  memcpy(lengthed_data+sizeof(data_len), data, data_len * sizeof(uint8_t));

  uint8_t* end_of_data = lengthed_data + data_len + sizeof(data_len);
  uint8_t* cur_data_offset = lengthed_data;
  PNGChunkData cur_data_chunk(cover_payload + c_magic_header_length, cover_payload + cover_len), next_data_chunk;

  while(cur_data_offset < end_of_data) {
    if (!cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)) {
      log_warn("Ran out of space while fiting the data into PNG cover");
      return -1;
    }
    cur_data_chunk = next_data_chunk;
    memcpy(cur_data_chunk.chunk_offset+8, cur_data_offset, cur_data_chunk.length);
    cur_data_offset += cur_data_chunk.length;

  }

  return 0;

}

ssize_t PNGSteg::decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data)
{
  //The assumption is that the data buffer can cantain the maximum size of the 
  //data
  //Make a new block of data with data length attached
  PNGChunkData cur_data_chunk((uint8_t*)cover_payload + c_magic_header_length, (uint8_t*)cover_payload + cover_len), next_data_chunk;

  //recovering data length
  size_t data_recovered_length = 0;
  while( data_recovered_length < sizeof(size_t)) {
    if (!cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)) {
      log_warn("Ran out of PNG cover before reocovering the whole data, something is wrong :'(, probably corrupted cover");
      return -1;
    }
    cur_data_chunk = next_data_chunk;
    memcpy(data + data_recovered_length, cur_data_chunk.chunk_offset,cur_data_chunk.length);
    data_recovered_length += cur_data_chunk.length;

  }
  
  //now we know the exact length 
  size_t data_length = (size_t)(*data);
  
  //moving stuff
  data_recovered_length -= sizeof(data_length);
  memcpy(data, data + sizeof(data_length), data_recovered_length);
  
  while(data_recovered_length < data_length) {
    if (!cur_data_chunk.get_next_IDAT_chunk(&next_data_chunk)) {
      log_warn("Ran out of PNG cover before reocovering the whole data, something is wrong :'(, probably corrupted cover");
      return -1;
    }
    cur_data_chunk = next_data_chunk;
    memcpy(data + data_recovered_length, cur_data_chunk.chunk_offset,cur_data_chunk.length);
    data_recovered_length += cur_data_chunk.length;

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
