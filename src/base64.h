/* Base-64 encoding and decoding.  Based on the libb64 project
   (http://sourceforge.net/projects/libb64) whose code is placed in the
   public domain. */

#ifndef ST_BASE64_H
#define ST_BASE64_H

#include <stddef.h>

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

public:
  decoder(char pl = '+', char sl = '/', char eq = '=')
    : step(step_A), plainchar(0),
      plus(pl), slash(sl), equals(eq)
  {}

  ptrdiff_t decode(const char* code_in, size_t length_in, char* plaintext_out);
  void reset() { step = step_A; plainchar = 0; }
};

} // namespace base64

#endif // ST_BASE64_H
