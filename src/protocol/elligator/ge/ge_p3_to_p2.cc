//
// ge_p3_to_p2.cc - SUPERCOP ed25519-ref10 ge_p3_to_p2.c
//

#include "elligator/ge/ge.h"

namespace elligator {


/*
r = p
*/

void ge_p3_to_p2(ge_p2 *r,const ge_p3 *p)
{
  r->X.copy(p->X);
  r->Y.copy(p->Y);
  r->Z.copy(p->Z);
}

} // namespace elligator
