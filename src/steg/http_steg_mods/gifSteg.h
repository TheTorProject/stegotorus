/**
   Copyright 2013 Tor Inc
   
   Steg Module to encode/decode data into gif images
   AUTHOR:
   - Vmon: Initial version, July 2013
*/ 
#ifndef __GIF_STEG_H
#define __GIF_STEG_H

class GIFSteg : public FileStegMod
{
protected:

   static const uint8_t c_image_block_sentinel = 0x2c; //','
   /**
     finds the 0x21 code in the file which is the begining of the image 
     block and then write the data till the end not overwriting the 0x3B
     ending code.

     @param cover_payload the gif file 
     @param cover_len     the size of the cover

     @return the start of the image block after sentinel where information can
             be stored -1 if no block found
   */
 	static ssize_t  starting_point(const uint8_t *cover_payload, size_t cover_len);

public:

    /**
       returns the capacity of the data you can store in gif response
       given the gif file content in 

       @param buffer: the buffer containing the payload
       @param len: the buffer's length

       @return the capacity that the buffer can cover or < 0 in case of error
     */
	virtual ssize_t capacity(const uint8_t *buffer, size_t len);
	static unsigned int static_capacity(char *buffer, int len);

    /**
       constructor just to call parent constructor
    */
   GIFSteg(PayloadServer* payload_provider, double noise2signal = 0);


    virtual int encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len);
    
	virtual ssize_t decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data);

};

#endif // __JPG_STEG_H
