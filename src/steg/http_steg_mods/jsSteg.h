/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JSSTEG_H
#define _JSSTEG_H

 class JSSteg : public FileStegMod
{

 protected:
  /**
     this function carry the only major part that is different between a
     js file and html file. As such html file will re-implement it accordingly
     As the result encode and decode function for both types remains the same.
     
     @param data the to be encoded data which is converted to hex characters 
            (two character represents an original binary byte)
     @param the original jTemplate the javascript cover which is supposed to
     contains the js data.

     @param the buffer which will contains the the new js script which hides
            the data in itself.

     @param dlen size of the data buffer.
     @param jtlen size of jTemplate buffer
     @param maximum jdlen size of jData

     @return 
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
  
  static unsigned int js_code_block_preliminary_capacity(char* buf, size_t len);

public:
  int isxString(char *str);

  int isGzipContent (char *msg);

  int findContentType (char *msg);


  /*int encode(char *data, char *jTemplate, char *jData,
           unsigned int dlen, unsigned int jtlen, unsigned int jdlen );*/

  JSSteg(PayloadServer* payload_provider, double noise2signal = 0, int content_type = HTTP_CONTENT_JAVASCRIPT); 

  virtual int encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len);
  
  virtual ssize_t decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data);

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


/*int decode (char *jData, char *dataBuf, unsigned int jdlen,
            unsigned int dlen, unsigned int dataBufSize );*/





void printerr(int err_no);

};

int encodeHTTPBody(char *data, char *jTemplate, char *jData, unsigned int dlen,
                   unsigned int jtlen, unsigned int jdlen, int mode);



int decodeHTTPBody (char *jData, char *dataBuf, unsigned int jdlen,
                    unsigned int dataBufSize, int *fin, int mode);

int isxString(char *str);

int isGzipContent (char *msg);

int findContentType (char *msg);

/*int testEncode(char *data, char *js, char *outBuf,
               unsigned int dlen, unsigned int jslen,
               unsigned int outBufLen, int testNum);

int testDecode(char *inBuf, char *outBuf, unsigned int inBufSize,
               unsigned int dlen,
               unsigned int outBufSize, int testNum);*/

/**These now correspond to current encode and decode
int testEncode2(char *data, char *js, char *outBuf,
                unsigned int dlen, unsigned int jslen, unsigned int outBufLen,
                int mode, int testNum);

int testDecode2(char *inBuf, char *outBuf,
             unsigned int inBufSize, unsigned int outBufSize,
                int mode, int testNum);**/
int encode_in_single_js_block(char *data, char *jTemplate, char *jData,
             unsigned int dlen, unsigned int jtlen,
             unsigned int jdlen, int *fin);
int decode_single_js_block(const char *jData, const char *dataBuf, unsigned int jdlen,
             unsigned int dataBufSize, int *fin );

int
http_server_JS_transmit (PayloadServer* pl, struct evbuffer *source,
                         conn_t *conn, unsigned int content_type);

int
http_handle_client_JS_receive(steg_t *s, conn_t *conn,
                              struct evbuffer *dest, struct evbuffer* source);



#endif
