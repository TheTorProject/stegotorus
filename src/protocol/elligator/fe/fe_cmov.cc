//
// fe_cmov.cc - SUPERCOP ed25519-ref10 fe_cmov.c
//

#include "elligator/fe/fe.h"

namespace elligator {

/*
Replace (f,g) with (g,g) if b == 1;
replace (f,g) with (f,g) if b == 0.

Preconditions: b in {0,1}.
*/

void FieldElement::cmov(const FieldElement& g,
                        unsigned int b) {
  crypto_int32 f0 = h[0];
  crypto_int32 f1 = h[1];
  crypto_int32 f2 = h[2];
  crypto_int32 f3 = h[3];
  crypto_int32 f4 = h[4];
  crypto_int32 f5 = h[5];
  crypto_int32 f6 = h[6];
  crypto_int32 f7 = h[7];
  crypto_int32 f8 = h[8];
  crypto_int32 f9 = h[9];
  crypto_int32 g0 = g[0];
  crypto_int32 g1 = g[1];
  crypto_int32 g2 = g[2];
  crypto_int32 g3 = g[3];
  crypto_int32 g4 = g[4];
  crypto_int32 g5 = g[5];
  crypto_int32 g6 = g[6];
  crypto_int32 g7 = g[7];
  crypto_int32 g8 = g[8];
  crypto_int32 g9 = g[9];
  crypto_int32 x0 = f0 ^ g0;
  crypto_int32 x1 = f1 ^ g1;
  crypto_int32 x2 = f2 ^ g2;
  crypto_int32 x3 = f3 ^ g3;
  crypto_int32 x4 = f4 ^ g4;
  crypto_int32 x5 = f5 ^ g5;
  crypto_int32 x6 = f6 ^ g6;
  crypto_int32 x7 = f7 ^ g7;
  crypto_int32 x8 = f8 ^ g8;
  crypto_int32 x9 = f9 ^ g9;
  b = -b;
  x0 &= b;
  x1 &= b;
  x2 &= b;
  x3 &= b;
  x4 &= b;
  x5 &= b;
  x6 &= b;
  x7 &= b;
  x8 &= b;
  x9 &= b;
  h[0] = f0 ^ x0;
  h[1] = f1 ^ x1;
  h[2] = f2 ^ x2;
  h[3] = f3 ^ x3;
  h[4] = f4 ^ x4;
  h[5] = f5 ^ x5;
  h[6] = f6 ^ x6;
  h[7] = f7 ^ x7;
  h[8] = f8 ^ x8;
  h[9] = f9 ^ x9;
}

} // namespace elligator
