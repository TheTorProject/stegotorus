//
// ge_p1p1_to_p3.cc - SUPERCOP ed25519-ref10 ge_p1p1_to_p3.c
//

#include "elligator/ge/ge.h"

namespace elligator {

/*
r = p
*/

void ge_p1p1_to_p3(ge_p3 *r,const ge_p1p1 *p)
{
  r->X.mul(p->X,p->T);
  r->Y.mul(p->Y,p->Z);
  r->Z.mul(p->Z,p->T);
  r->T.mul(p->X,p->Y);
}

} // namespace elligator
