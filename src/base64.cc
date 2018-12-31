/* Base-64 encoding and decoding.  Based on the libb64 project
   (http://sourceforge.net/projects/libb64) whose code is placed in the
   public domain. */

#include "base64.h"
#include <stdlib.h>

const int CHARS_PER_LINE = 72;

static char
encode1(unsigned int value, char plus, char slash, char eq)
{
  const char encoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "abcdefghijklmnopqrstuvwxyz0123456789+/";
  if (value > sizeof encoding - 1)
    return eq;

  char rv = encoding[value];
  if (rv == '+')
    return plus;
  else if (rv == '/')
    return slash;
  else
    return rv;
}

/* assumes ASCII */
static int
decode1(unsigned int value, char plus, char slash)
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

  if (value == (unsigned int)plus)
    value = '+';
  else if (value == (unsigned int)slash)
    value = '/';

  value -= 43;
  if (value > sizeof(decoding))
    return -1;
  return decoding[value];
}

namespace base64
{

ptrdiff_t
encoder::encode(const char* plaintext_in, size_t length_in, char* code_out)
{
  const char* plainchar = plaintext_in;
  const char* const plaintextend = plaintext_in + length_in;
  char* codechar = code_out;
  char result;
  char fragment;

  result = this->result;

  switch (this->step) {
    for (;;) {
    case step_A:
      if (plainchar == plaintextend) {
        this->result = result;
        this->step = step_A;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result = (fragment & 0x0fc) >> 2;
      *codechar++ = encode1(result, plus, slash, equals);
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
      *codechar++ = encode1(result, plus, slash, equals);
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
      *codechar++ = encode1(result, plus, slash, equals);
      result  = (fragment & 0x03f) >> 0;
      *codechar++ = encode1(result, plus, slash, equals);

      if (wrap) {
        ++(this->stepcount);
        if (this->stepcount == CHARS_PER_LINE/4) {
          *codechar++ = '\n';
          this->stepcount = 0;
        }
      }
    }
  default:
    abort();
  }
}

ptrdiff_t
encoder::encode_end(char* code_out)
{
  char* codechar = code_out;

  switch (this->step) {
  case step_B:
    *codechar++ = encode1(this->result, plus, slash, equals);
    *codechar++ = equals;
    *codechar++ = equals;
    break;
  case step_C:
    *codechar++ = encode1(this->result, plus, slash, equals);
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

ptrdiff_t
decoder::decode(const char* code_in, size_t length_in, char* plaintext_out)
{
  const char* codechar = code_in;
  char* plainchar = plaintext_out;
  int fragment;

  *plainchar = this->plainchar;

  switch (this->step) {
    while (1) {
    case step_A:
      do {
        if (codechar == code_in+length_in) {
          this->step = step_A;
          this->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = decode1(*codechar++, plus, slash);
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
        fragment = decode1(*codechar++, plus, slash);
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
        fragment = decode1(*codechar++, plus, slash);
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
        fragment = decode1(*codechar++, plus, slash);
      } while (fragment < 0);
      *plainchar++   |= (fragment & 0x03f);
    }
  default:
    abort();
  }
}

} // namespace base64
