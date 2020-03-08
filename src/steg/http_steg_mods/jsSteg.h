/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JSSTEG_H
#define _JSSTEG_H

// JS_DELIMITER that exists in the JavaScript before the end of
// data encoding will be replaced by JS_DELIMITER_REPLACEMENT
#define JS_DELIMITER_SIZE 1

// error codes
#define INVALID_BUF_SIZE	-1
#define INVALID_DATA_CHAR	-2

// controlling content gzipping for jsSteg
#define JS_GZIP_RESP             0

// jsSteg-specific defines
#define JS_DELIMITER '?'
// a JavaScript delimiter is used to signal the end of encoding
// to facilitate the decoding process
#define JS_DELIMITER_REPLACEMENT '!'

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
  virtual ssize_t decode_http_body(const std::vector<uint8_t>& cover_and_data, std::vector<uint8_t>& data, int& fin);
                      
  
  /**
     compute the maximum size of data in bytes which can be embeded in a js code block/file

     @param block_start an iterator to the beginning of the block.
     @param block_len   the length of the block in bytes.

     @return the number of bytes can be embeded in the block (0 if none is possible or errornous block)
   */
  static size_t js_code_block_preliminary_capacity(std::vector<uint8_t>::const_iterator block_start, const size_t block_len);

  /**
   Embed the data in  a single block of java script code. If all data are embeded it fill up the the rest of the payload with the original cover. JSSteg calls it only once html steg should call it multiple times.
   
   @param cover the buffer which contains the original cover
   @param cover_it the iterator of first unconsumed cover byte
   @param data_it the iterator pointing at the first unembeded data byte
   @param end_of_data an iterator pointing at the end of the data to be embedded
   @param cover_and_data_it an iterator to the place in the buffer which eventually will contains the cover 
          with data embeded inside it. The vector should be of approperiate size
   @param end_of_block an iterator to the place in the cover where current block ends
   @param fin actually a second return value indicating that if we were able to encode all data given or not

   @return the number data bytes successfully embeded or
           negative values of INVALID_BUF_SIZE or INVALID_DATA_CHAR in
           case of error
  */
  ssize_t encode_in_single_js_block(vector<uint8_t>::const_iterator cover_it, const vector<uint8_t>::const_iterator  end_of_block, vector<uint8_t>::const_iterator  data_it, vector<uint8_t>::const_iterator  end_of_data, vector<uint8_t>::iterator cover_and_data_it, int& fin);

  /**
     for a single block of js code, this could be an entire js script file or 
     a block of js script inside an html file, it decode the data embeded into
     it.

     @param cover_and_data_it iterator pointing at the first byte of the block
     @param end_of_block_pos iterator pointing at the end of the block
     @param data the buffer which will grow to contain the extracted data
     @param fin actually a second return value indicating that we read an the 
            indicator that the all data has been read

     @return the number data bytes successfully embeded or
           negative values of INVALID_BUF_SIZE or INVALID_DATA_CHAR in
           case of error
 */
  ssize_t decode_single_js_block(std::vector<uint8_t>::const_iterator cover_and_data_it, const std::vector<uint8_t>::const_iterator end_of_block_pos, std::vector<uint8_t>& data, int& fin);

  static int skipJSPattern(const uint8_t *cp, int len);

public:
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
  static int offset2Hex (const unsigned char *p, int range, int isLastCharHex);

};

#endif
