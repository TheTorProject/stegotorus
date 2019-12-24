/* Copyright 2011, 2012 SRI International
 * Copyright 2016 ASL19 Inc.
 * See LICENSE for other credits and copying information
 */

#ifndef _HTMLSTEG_H
#define _HTMLSTEG_H

#include "jsSteg.h"

/**
   This is a child of js steg class, its embed the information in the 
   js function embeded in an html file.

 */

class HTMLSteg : public JSSteg
{
protected:
  static const std::string c_js_block_start_tag;
  static const std::string c_js_block_end_tag;
  
public:
    HTMLSteg(PayloadServer& payload_provider, double noise2signal = 0); 

    /**
       compute the capcaity of the cover by getting a pointer to the
       beginig of the body in the response

       @param cover_body pointer to the begiing of the body
       @param body_length the total length of message body
    */
    virtual ssize_t headless_capacity(const std::vector<uint8_t>& cover_body);

    /**
     this function carry the only major part of encoding that is different between a
     js file and html file. As such html file will re-implement it accordingly
     As the result encode and decode function for both types remains the same.
    */
    virtual ssize_t encode_http_body(const std::vector<uint8_t>& data, const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& cover_and_data);

    /**
       this function carry the only major part of decoding that is different between a
       js file and html file. As such html file will re-implement it accordingly
       As the result encode and decode function for both types remains the same.
    */
  virtual ssize_t decode_http_body(const std::vector<uint8_t>& cover_and_data, std::vector<uint8_t>& data, int& fin);

};

#endif
