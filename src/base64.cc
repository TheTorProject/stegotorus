/* Copyright 2012-2019 The Tor Project Inc.
 * See LICENSE for other credits and copying information
 */

/* Base-64 encoding and decoding.  Based on the libb64 project
   (http://sourceforge.net/projects/libb64) whose code is placed in the
   public domain. */

#include <stdlib.h>

#include "base64.h"
#include "util.h"

const int CHARS_PER_LINE = 72;

using namespace std;

namespace base64
{

/**
   gets one 1/4 of 3 bytes already reduced to a value between 
   0-63 and returns the curresponding base64 encoding respecting 
   the value for plus and slash. Panics if value is out of range.

   @param value a value between 0 and 63 inclusively.

 */
char
encoder::encode_one_chunk(unsigned int value)
{
  log_assert(value <= 63);
  const char encoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "abcdefghijklmnopqrstuvwxyz0123456789+/";
  if (value > sizeof encoding - 1)
    return this->equals;

  char readable_base64_char = encoding[value];
  if (readable_base64_char == '+')
    return plus;
  else if (readable_base64_char == '/')
    return slash;
  else
    return readable_base64_char;
}

/**
   given a valid readable base64 character returns the byte value 0-63 corresponding
   to the character. panics if it receives invalid character.

   @param value ascii code of a capital or a small letter, a digits or plus, slash.
*/
unsigned int
decoder::decode_one_chunk(unsigned int value)
{
  const signed char decoding[] = {
    //  +   ,   -   .   /   0   1   2   3   4   5   6   7   8   9
       62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    //  :   ;   <   =   >   ?   @
       -1, -1, -1, -1, -1, -1, -1,
    //  A   B   C   D   E   F   G   H   I   J   K   L   M
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
    //  N   O   P   Q   R   S   T   U   V   W   X   Y   Z
       13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    //  [   \   ]   ^   _   `
       -1, -1, -1, -1, -1, -1,
    //  a   b   c   d   e   f   g   h   i   j   k   l   m
       26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    //  n   o   p   q   r   s   t   u   v   w   x   y   z
       39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
  };

  int decoded_value = -1;

  if (value == (unsigned int)plus)
    value = '+';
  else if (value == (unsigned int)slash)
    value = '/';

  if (43 <= value && value < sizeof(decoding) + 43)
    decoded_value = decoding[value - 43];

  //log_assert(decoded_value >= 0);
  return static_cast<unsigned int>(decoded_value);
}

/**
   encode a blob into base64 with encoding 3 characters at the time
   (step_A,B and C) generating 4 base64 character at each iteration.
   it keeps the current step as a class property, it assumes that
   it is the continuation of last call to encode unless encode_end
   is called.

   @param code_out MUST be a pointer to a buffer of size 
   ceiling(length_in * 4/3)

   @return the actual size of the encoded data

 */
ptrdiff_t
encoder::encode(const char* plaintext_in, size_t length_in, char* code_out)
{
  
  const char* plainchar = plaintext_in;
  const char* const plaintextend = plaintext_in + length_in;
  char* codechar = code_out;
  char result;
  char fragment;

  //TODO: this is violating oop why are you equatinga local variable and a class one?
  //This is designed to be called sequentially for examlpe reading from a file so
  //it needs to keep state.
  result = this->result;

  for (;;) { //each for encode one character and loops over steps step C generate two characters
    switch (this->step) {
    case step_A:
      if (plainchar == plaintextend) {
        this->result = result;
        this->step = step_A;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result = (fragment & 0x0fc) >> 2;
      *codechar++ = encode_one_chunk(result);
      result = (fragment & 0x003) << 4;
      //fallthrough
    case step_B:
      if (plainchar == plaintextend) {
        this->result = result;
        this->step = step_B;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result |= (fragment & 0x0f0) >> 4;
      *codechar++ = encode_one_chunk(result);
      result = (fragment & 0x00f) << 2;
      //fallthrough
    case step_C:
      if (plainchar == plaintextend) {
        this->result = result;
        this->step = step_C;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result |= (fragment & 0x0c0) >> 6;
      *codechar++ = encode_one_chunk(result);
      result  = (fragment & 0x03f) >> 0;
      *codechar++ = encode_one_chunk(result);

      if (wrap) {
        ++(this->stepcount);
        if (this->stepcount == CHARS_PER_LINE/4) {
          *codechar++ = '\n';
          this->stepcount = 0;
        }
      }
      break;
  default:
    log_abort("logical error during base64 encoding");
    }
  }
}

/**
 * TODO: document the size of de_out 
 * TODO: code_out should be a smart poniter.
 * 
 */
ptrdiff_t
encoder::encode_end(char* code_out)
{
  char* codechar = code_out;

  switch (this->step) {
  case step_B:
    *codechar++ = encode_one_chunk(this->result);
    *codechar++ = equals;
    *codechar++ = equals;
    break;
  case step_C:
    *codechar++ = encode_one_chunk(this->result);
    *codechar++ = equals;
    break;
  case step_A:
    break;
  }
  if (wrap)
    *codechar++ = '\n';
  *codechar = '\0';

  /* reset */
  this->step = step_A;
  this->stepcount = 0;
  this->result = 0;
  return codechar - code_out;
}

/**
 * sequentially decode a base64 buffers to binary 
 * 
 * @param plaintext_out MUST have at least ceiling(length_in * 3/4) bytes allocated
 * 
 * @return the actual size of the decoded data
 */

ptrdiff_t
decoder::decode(const char* code_in, size_t length_in, char* plaintext_out)
{
  const char* codechar = code_in;
  char* plainchar = plaintext_out;
  int fragment;

  *plainchar = this->plainchar;

  for(;;) { 
  switch (this->step) {
    case step_A:
      do {
        if (codechar == code_in+length_in) {
          this->step = step_A;
          this->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = decode_one_chunk(*codechar++);
      } while (fragment < 0);
      *plainchar = (fragment & 0x03f) << 2;
      //fallthrough
    case step_B:
      do {
        if (codechar == code_in+length_in) {
          this->step = step_B;
          this->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = decode_one_chunk(*codechar++);
      } while (fragment < 0);
      *plainchar++ |= (fragment & 0x030) >> 4;
      *plainchar    = (fragment & 0x00f) << 4;
      //fallthrough
    case step_C:
      do {
        if (codechar == code_in+length_in) {
          this->step = step_C;
          this->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = decode_one_chunk(*codechar++);
      } while (fragment < 0);
      *plainchar++ |= (fragment & 0x03c) >> 2;
      *plainchar    = (fragment & 0x003) << 6;
      //fallthrough
    case step_D:
      do {
        if (codechar == code_in+length_in) {
          this->step = step_D;
          this->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = decode_one_chunk(*codechar++);
      } while (fragment < 0);
      *plainchar++   |= (fragment & 0x03f);
      break;
  default:
    log_abort("logical error during base64 decoding");
  }
  }
}

} // namespace base64
