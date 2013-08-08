/**
   Copyright 2013 Tor Inc
   
   Steg Module to encode/decode data into png images
   AUTHOR:
   - Vmon: Initial version, July 2013

*/
#ifndef __PNG_STEG_H
#define __PNG_STEG_H

#include <assert.h>

class PNGChunkData
{
 protected:
  /**
     Reads the first four bytes the offset is pointing to and compute the chunk's length
     check for the chunk validity first
  */
  inline void compute_length()
  {
    assert(chunk_offset);
    length = (*(chunk_offset + 0) << 24) | (*(chunk_offset+1) << 16) | (*(chunk_offset+2) << 8) | *(chunk_offset + 3);
  }

 public:
  uint8_t* chunk_offset;
  uint8_t* payload_end;
  const char* type = "IDAT";
  static const size_t chunk_header_footer_length = 12;
  size_t length;
  
  /**
     retrieve the next chunk data using the this chunk data 
     
     @param next_chunk_data pointer to the object which is going to store the next chunk
            data

     @return next chunk offset or 0 if not found

  */
  uint8_t* get_next_IDAT_chunk(PNGChunkData* next_chunk)
  {
    assert(chunk_offset);

    next_chunk->chunk_offset = chunk_offset + length + chunk_header_footer_length;
    next_chunk->compute_length();

    while(next_chunk->chunk_offset < payload_end) {
      if  (!memcmp(type, next_chunk->chunk_offset + 4, 4 * sizeof(uint8_t)))
        return next_chunk->chunk_offset;

      next_chunk->chunk_offset += next_chunk->length + (size_t)12;
      next_chunk->compute_length();
           
    }

    //reached the end of payload
    return 0;

  }

  /**
     default constructor nulify everything so we know it is un
  */
  PNGChunkData()
    :chunk_offset(0), payload_end(0),length(0)
    {
    }

  /**
     find the next IDAT chunk and initiate the object with its
     data
     
     @param the offset of a chunk (not necessarly IDAT) occures somewhere before the
            IDAT chunk, if it is 0, it will be moved to 8, end of the magic data
            and the begining of the chunk
  */
  PNGChunkData(uint8_t* cur_chunk_offset, uint8_t* payload_end)
    :PNGChunkData()
    {
      PNGChunkData aux_chunk;
      aux_chunk.chunk_offset = cur_chunk_offset;
      aux_chunk.payload_end = payload_end;
      aux_chunk.compute_length();
      assert(aux_chunk.get_next_IDAT_chunk(this));
      
    }

};


class PNGSteg : public FileStegMod
{
public:

    /**
       returns the capacity of the data you can store in png IDAT chunks

       @param buffer: the buffer containing the payload
       @param len: the buffer's length

       @return the capacity that the buffer can cover or < 0 in case of error
     */
	virtual ssize_t capacity(const uint8_t *buffer, size_t len);
	static unsigned int static_capacity(char *buffer, int len);

    /**
       constructor just to call parent constructor
    */
   PNGSteg(PayloadServer* payload_provider, double noise2signal = 0);

protected:
   const string c_data_chunk_type = "IDAT";
   static const size_t c_magic_header_length = 8;

   virtual int encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len);
    
	virtual ssize_t decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data);

};

#endif // __PNG_STEG_H
