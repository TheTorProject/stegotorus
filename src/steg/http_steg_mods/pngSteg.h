/**
   Copyright 2013 Tor Inc
   
   Steg Module to encode/decode data into png images
   AUTHOR:
   - Vmon: Initial version, July 2013

*/
#ifndef __PNG_STEG_H
#define __PNG_STEG_H

#include <vector>
#include <assert.h>

class PNGChunkData
{
 protected:
    bool uninitialized_chunk = true; // a boolean flag which indicate we actually
  //the chunk hasn't been initialized with a valid chunk_offset and payload_end 
  //yet cause there is no nillptr for STL iterators

  /**
     Reads the first four bytes the offset is pointing to and compute the chunk's length
     check for the chunk validity first
  */
  void compute_length()
  {

    //if we already detected that the file format is invalid it is a bug
    //to call this function
    //And
    //it is a protocted function so we shouldn't call it before initializing
    //the chunk
    log_assert(!(invalid_file_format || uninitialized_chunk));

    length =
      (uninitialized_chunk == false) &&
      (chunk_offset != payload_end) &&
      (chunk_offset + 3 < payload_end)
      ?
      (*(chunk_offset + 0) << 24) | (*(chunk_offset+1) << 16) | (*(chunk_offset+2) << 8) | *(chunk_offset + 3)
      : 0;
    if (chunk_offset + length + chunk_header_footer_length > payload_end) {
      invalid_file_format = true;
      length = 0;
    }
  }

 public:
  std::vector<uint8_t>::const_iterator chunk_offset;
  std::vector<uint8_t>::const_iterator payload_end;
  const std::vector<uint8_t> type = {'I','D','A','T'};
  static const size_t c_chunk_header_length = 8;
  static const size_t chunk_header_footer_length = 12;
  size_t length = 0;
  
  bool invalid_file_format = false; // a boolean flag which if it is true, it
  //is indicating that we detected a corrupted file format
  
  /**
     retrieve the next chunk data using the this chunk data 
     
     @param next_chunk_data reference to the object which is going to store the next chunk
            data

     @return boolean value true if retrieving next chunk was successful false otherwise

  */
  bool get_next_IDAT_chunk(PNGChunkData& next_chunk)
  {
    if (uninitialized_chunk) {
      return false;
    }

    if (chunk_offset + length + chunk_header_footer_length > payload_end) {
      invalid_file_format = true;
      return false;
    }

    next_chunk.chunk_offset = chunk_offset + length + chunk_header_footer_length;
    next_chunk.payload_end = payload_end;
    next_chunk.uninitialized_chunk = false;
    next_chunk.compute_length();

    //If the length is invalid then the file is either corrupted or invalid format
    if (next_chunk.invalid_file_format) {
      return false;
    }

    while(next_chunk.chunk_offset < payload_end) {
      if  (std::equal(type.begin(), type.end(), next_chunk.chunk_offset + 4)) {
        //we found a data chunk we just check it is valid
        return  true;

      }

      //it is not a data chunk so let's go to next chunk if it is possible
      if (next_chunk.chunk_offset + next_chunk.length + chunk_header_footer_length > payload_end) {
        next_chunk.invalid_file_format = true;
        return false; //corrupted: something is wrong!
      }

      next_chunk.chunk_offset += next_chunk.length + chunk_header_footer_length;
      next_chunk.compute_length();

      //make sure length made sense
      if (next_chunk.invalid_file_format)
        return false;
           
    }

    //reached the end of payload
    return false;

  }

  PNGChunkData operator=(PNGChunkData& RHS) {
    this->chunk_offset = RHS.chunk_offset;
    this->payload_end = RHS.payload_end;
    this->length = RHS.length;
    this->invalid_file_format = RHS.invalid_file_format;
    this->uninitialized_chunk = RHS.uninitialized_chunk;

    return *this;
  }

  /*
    copy constructor 
  */
  PNGChunkData(PNGChunkData& RHS) {
    this->chunk_offset = RHS.chunk_offset;
    this->payload_end = RHS.payload_end;
    this->length = RHS.length;
    this->invalid_file_format = RHS.invalid_file_format;
    this->uninitialized_chunk = RHS.uninitialized_chunk;
  }

  /**
     default constructor which generates uninitialized chunks 
     without valid payload_end
   */
  PNGChunkData()
  {
    // so unitialized_chunk == true
  }
  
  /**
     constructor which finds the next IDAT chunk after the given chuck
     and initiate the object with its data
     
     @param the offset of a chunk (not necessarly IDAT) occures somewhere before the
            IDAT chunk, if it is 0, it will be moved to 8, end of the magic data
            and the begining of the chunk
  */
  PNGChunkData(vector<uint8_t>::const_iterator cur_chunk_offset, vector<uint8_t>::const_iterator payload_end)
    {
      PNGChunkData aux_chunk;
      aux_chunk.chunk_offset = cur_chunk_offset;
      aux_chunk.payload_end = payload_end;
      aux_chunk.uninitialized_chunk = false; //we set cur_chunk_offset and payload_end so it is initialized. QED.
      aux_chunk.compute_length();

      if (aux_chunk.invalid_file_format) {
        this->invalid_file_format = true;
      } else if (!aux_chunk.get_next_IDAT_chunk(*this)) {
        this->invalid_file_format = true;
      }
        
    }
};


class PNGSteg : public FileStegMod
{
protected:
   static const size_t c_magic_header_length = 8;

public:

    /**
       compute the capcaity of the cover by getting a pointer to the
       beginig of the body in the response

       @param cover_body pointer to the begiing of the body
       @param body_length the total length of message body
    */
    virtual ssize_t headless_capacity(const std::vector<uint8_t>& cover_body);


    /**
       constructor just to call parent constructor
    */
   PNGSteg(PayloadServer& payload_provider, double noise2signal = 0);

   virtual ssize_t encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payload);
    
   virtual ssize_t decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data);

};

#endif // __PNG_STEG_H
