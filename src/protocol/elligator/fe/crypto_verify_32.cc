//
// crypto_verify_32.cc - SUPERCOP ed25519-ref10 crypto_verify_32.cc
//

#include "elligator/fe/fe.h"

namespace elligator {

int crypto_verify_32(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  F(16)
  F(17)
  F(18)
  F(19)
  F(20)
  F(21)
  F(22)
  F(23)
  F(24)
  F(25)
  F(26)
  F(27)
  F(28)
  F(29)
  F(30)
  F(31)

  // return (1 & ((differentbits - 1) >> 8)) - 1;

  /*
   * Note: The original code returns 0 or -1 which is not suitable for
   * fe_cmov, which expects 0 or 1, so fix up the return value in constant
   * time.
   */

  unsigned mask = - (1 & ((differentbits - 1) >> 8)) - 1;
  unsigned ret = mask & (0^1);
  ret = ret ^ 0;
  return ret;
}

} // namespace elligator
