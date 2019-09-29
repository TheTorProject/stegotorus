/* Copyright 2019 The Tor Project Inc.
 * See LICENSE for other credits and copying information
 */

/* Base-64 encoding and decoding.  Based on the libb64 project
   (http://sourceforge.net/projects/libb64) whose code is placed in the
   public domain. */

#ifndef ST_BASE64_H
#define ST_BASE64_H

#include <stddef.h>
#include <memory>

namespace base64
{

class encoder
{
  enum encode_step { step_A, step_B, step_C };
  encode_step step;
  int stepcount;
  char result;
  char plus;
  char slash;
  char equals;
  bool wrap;

  /**
   gets one 1/4 of 3 bytes already reduced to a value between 
   0-63 and returns the curresponding base64 encoding respecting 
   the value for plus and slash. Panics if value is out of range.

   @param value a value between 0 and 63 inclusively.

 */
  char encode_one_chunk(unsigned int value);

public:
  // The optional arguments to the constructor allow you to disable
  // line-wrapping and/or replace the characters used to encode digits
  // 62 and 63 and padding (normally '+', '/', and '=' respectively).
  encoder(bool wr = true, char pl = '+', char sl = '/', char eq = '=')
    : step(step_A), stepcount(0), result(0),
      plus(pl), slash(sl), equals(eq), wrap(wr)
  {}

    ptrdiff_t encode(const char* plaintext_in, size_t length_in, char* code_out);
    ptrdiff_t encode_end(char* code_out);
};

class decoder
{
  enum decode_step { step_A, step_B, step_C, step_D };
  decode_step step;
  char plainchar;
  char plus;
  char slash;
  char equals;
  bool wrap;

   /**
   given a valid readable base64 character returns the byte value 0-63 corresponding
   to the character. panics if it receives invalid character.

   @param value ascii code of a capital or a small letter, a digits or plus, slash.
  */
  unsigned int decode_one_chunk(unsigned int value);

public:
  decoder(char pl = '+', char sl = '/', char eq = '=')
    : step(step_A), plainchar(0),
      plus(pl), slash(sl), equals(eq)
  {(void)equals; (void)wrap;}

/**
 * sequentially decode a base64 buffers to binary 
 * 
 * @param plaintext_out MUST have at least ceiling(length_in * 3/4) bytes allocated
 * 
 * @return the actual size of the decoded data
 */
    ptrdiff_t decode(const char* code_in, size_t length_in, char* plaintext_out);
  void reset() { step = step_A; plainchar = 0; }
};

} // namespace base64

#endif // ST_BASE64_H
