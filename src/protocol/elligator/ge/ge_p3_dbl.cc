//
// ge_p3_dbl.cc - SUPERCOP ed25519-ref10 ge_p3_dbl.c
//

#include "elligator/ge/ge.h"

namespace elligator {

/*
r = 2 * p
*/

void ge_p3_dbl(ge_p1p1 *r,const ge_p3 *p)
{
  ge_p2 q;
  ge_p3_to_p2(&q,p);
  ge_p2_dbl(r,&q);
}

} // namespace elligator
