/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JSSTEG_H
#define _JSSTEG_H

class JSSteg : public FileStegMod
{

 protected:
  //this buffer is a helper buffer for compression/deflation
  //it is at class scope to avoid the penaltiy of allocation
  //delocation during process of each payload
  std::vector<uint8_t> outbuf2;

  /**
     this function carry the only major part that is different between a
     js file and html file. As such html file will re-implement it accordingly
     As the result encode and decode function for both types remains the same.
     
     @param data the to be encoded data which is converted to hex characters 
            (two character represents an original binary byte)
     @param cover_payload the original jTemplate the javascript cover which is supposed to
     contains the js data.

     @param cover_and_data the buffer which will contains the the new js script which hides
            the data in itself.

     @return the size of the new js cover which contains the data
   */
  virtual ssize_t encode_http_body(const std::vector<uint8_t>& data, const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& cover_and_data);

  /**
   this function carry the only major part of decoding that is different between a
   js file and html file. As such html file will re-implement it accordingly
   As the result encode and decode function for both types remains the same.

   @param cover_and_data the buffer containing the payload which contains the transported data
   @param data the buffer which will contain extracted data after decoding cover_and_data buffer
   @param fin an indicator signaling success or failure of the decoding

   @return length of recovered data

  */
  virtual size_t decode_http_body(const std::vector<uint8_t>& cover_and_data, std::vector<uint8_t>& data, int& fin);
                      
  
  static unsigned int js_code_block_preliminary_capacity(const char* buf, const size_t len);

    ssize_t  encode_in_single_js_block(const vector<uint8_t>& data, const vector<uint8_t>& cover, vector<uint8_t>& cover_and_data, size_t  data_offset, size_t cover_offset, size_t js_block_size, int& fin);

  /*
  for a single block of js code, this could be an entire js script file or 
  a block of js script inside an html file, it decode the data embeded into
  it.

   @param cover_and_data the buffer which contains the cover with data embeded inside it.
   @param data the buffer which will contain the extracted data
   @param cover_offset the index of first untreated cover byte
   @param data_offset the index of where to store data in data buffer
   @param js_block_size the size of the js code block, we need to decode the 
          data from cover_offset till js_block_size
   @param fin actually a second return value indicating that ?


   @return the number data bytes successfully embeded or
           negative values of INVALID_BUF_SIZE or INVALID_DATA_CHAR in
           case of error
 */
  ssize_t decode_single_js_block(const std::vector<uint8_t>& cover_and_data, std::vector<uint8_t>& data, size_t cover_offset, size_t data_offset, size_t js_block_size, int& fin );


public:
  int isGzipContent (char *msg);

  int findContentType (char *msg);

  /*int encode(char *data, char *jTemplate, char *jData,
           unsigned int dlen, unsigned int jtlen, unsigned int jdlen );*/

  JSSteg(PayloadServer& payload_provider, double noise2signal = 0, int content_type = HTTP_CONTENT_JAVASCRIPT); 

  virtual ssize_t encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payloadw);
  
  virtual ssize_t decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data);

  virtual ssize_t headless_capacity(const std::vector<uint8_t>& cover_body);

  /*int decode (char *jData, char *dataBuf, unsigned int jdlen,
            unsigned int dlen, unsigned int dataBufSize );*/
   void printerr(int err_no);

  /**
   * offset2Hex returns the offset to the next usable hex char.
   * usable here refer to char that our steg module can use to encode
   * data. in particular, words that correspond to common JavaScript keywords
   * are not used for data encoding (see skipJSPattern). Also, because
   * JS var name must start with an underscore or a letter (but not a digit)
   * we don't use the first char of a word for encoding data
   *
   * e.g., the JS statement "var a;" won't be used for encoding data
   * because "var" is a common JS keyword and "a" is the first char of a word
   *
   * @param p ptr to the starting pos 
   * @param range max number of char to look
   * @param isLastCharHex is the char pointed to by (p-1) a hex char 
   *
   * @return  offset2Hex returns the offset to the next usable hex char
   *           between p and (p+range), if it exists; otherwise, it 
   *           returns -1
   */
  static int offset2Hex (const char *p, int range, int isLastCharHex);

};

int encodeHTTPBody(char *data, char *jTemplate, char *jData, unsigned int dlen,
                   unsigned int jtlen, unsigned int jdlen, int mode);



int decodeHTTPBody (char *jData, char *dataBuf, unsigned int jdlen,
                    unsigned int dataBufSize, int *fin, int mode);

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

  /**
   Embed the data in  a single block of java script code. JSSteg calls it only 
   once html steg should call it multiple times.
   
   @param data the entire data to be embedded (possibly in multiple block)
          must be encoded in hex.
   @param cover the buffer which contains the virgin cover
   @param cover_and_data the buffer which eventually will contains the cover 
          with data embeded inside it.
   @param data_offset the index of first unembeded data byte
   @param cover_offset the index of first unused cover byte
   @param js_block_size the size of the js code block, we need to encode the 
          data from data_offset till js_block_size
   @param fin actually a second return value indicating that ?


   @return the number data bytes successfully embeded or
           negative values of INVALID_BUF_SIZE or INVALID_DATA_CHAR in
           case of error
 */

int
http_server_JS_transmit (PayloadServer* pl, struct evbuffer *source,
                         conn_t *conn, unsigned int content_type);

int
http_handle_client_JS_receive(steg_t *s, conn_t *conn,
                              struct evbuffer *dest, struct evbuffer* source);



#endif
