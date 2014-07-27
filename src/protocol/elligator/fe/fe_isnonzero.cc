//
// fe_isnonzero.cc - SUPERCOP ed25519-ref10 fe_isnonzero.c
//

#include "elligator/fe/fe.h"

namespace elligator {

/*
return 1 if f == 0
return 0 if f != 0

Preconditions:
   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

static const unsigned char fe_zero[32] = { 0 };

int FieldElement::isnonzero() const {
  unsigned char s[32];
  toBytes(s);
  return  crypto_verify_32(s,fe_zero);
}

} // namespace elligator
