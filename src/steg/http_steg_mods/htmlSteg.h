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

public:
    HTMLSteg(PayloadServer* payload_provider, double noise2signal = 0); 

    /**
       compute the capcaity of the cover by getting a pointer to the
       beginig of the body in the response

       @param cover_body pointer to the begiing of the body
       @param body_length the total length of message body
    */
    virtual ssize_t headless_capacity(char *cover_body, int body_length);
    static unsigned int static_headless_capacity(char *buf, size_t len);

    virtual ssize_t capacity(const uint8_t *cover_payload, size_t len);
    static unsigned int static_capacity(char *cover_payload, int body_length);

    /**
     this function carry the only major part of encoding that is different between a
     js file and html file. As such html file will re-implement it accordingly
     As the result encode and decode function for both types remains the same.
    */
    virtual int encode_http_body(const char *data, char *jTemplate, char *jData,
                   unsigned int dlen, unsigned int jtlen,
                             unsigned int jdlen);

    /**
       this function carry the only major part of decoding that is different between a
       js file and html file. As such html file will re-implement it accordingly
       As the result encode and decode function for both types remains the same.
    */
    virtual int decode_http_body(const char *jData, const char *dataBuf, unsigned int jdlen,
                       unsigned int dataBufSize, int *fin );

};



#endif
