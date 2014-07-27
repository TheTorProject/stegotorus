//
// ge_precomp_0.cc - SUPERCOP ed25519-ref10 ge_precomp_0.c
//

#include "elligator/ge/ge.h"

namespace elligator {

void ge_precomp_0(ge_precomp *h)
{
  h->yplusx.one();
  h->yminusx.one();
  h->xy2d.zero();
}

} // namespace elligator
