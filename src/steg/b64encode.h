/*
  cencode.h - c header for a base64 encoding algorithm

  This is part of the libb64 project, and has been placed in the public domain.
  For details, see http://sourceforge.net/projects/libb64
*/

#ifndef BASE64_CENCODE_H
#define BASE64_CENCODE_H

enum base64_encodestep
{
  step_A, step_B, step_C
};

struct base64_encodestate
{
  base64_encodestep step;
  char result;
  int stepcount;
};

void base64_init_encodestate(base64_encodestate* state_in);
char base64_encode_value(char value_in);
int base64_encode_block(const char* plaintext_in, int length_in,
                        char* code_out, base64_encodestate* state_in);

int base64_encode_blockend(char* code_out, base64_encodestate* state_in);

static int BUFFERSIZE = 16777216;

namespace base64
{
  struct encoder
  {
    base64_encodestate _state;
    int _buffersize;

    encoder(int buffersize_in = BUFFERSIZE)
    : _buffersize(buffersize_in)
    {}

    int encode(char value_in)
    {
      return base64_encode_value(value_in);
    }

    int encode(const char* code_in, const int length_in, char* plaintext_out)
    {
      base64_init_encodestate(&_state);
      return base64_encode_block(code_in, length_in, plaintext_out, &_state);
    }

    int encode_end(char* plaintext_out)
    {
      return base64_encode_blockend(plaintext_out, &_state);
    }
  };

} // namespace base64

#endif /* BASE64_CENCODE_H */
