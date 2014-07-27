//
// ge_p3_0.cc - SUPERCOP ed25519-ref10 ge_p3_0.c
//

#include "elligator/ge/ge.h"

namespace elligator {

void ge_p3_0(ge_p3 *h)
{
  h->X.zero();
  h->Y.one();
  h->Z.one();
  h->T.zero();
}

} // namespace elligator
