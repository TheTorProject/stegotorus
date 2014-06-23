//
// This is the group element code taken from the ref10 ed25519 implementation
// provided in SUPERCOP.  Any porting errors are mine alone.
//

#ifndef ELLIGATOR_GE_GE_H__
#define ELLIGATOR_GE_GE_H__

#include <stdint.h>

#include "elligator/fe/fe.h"

namespace elligator {

typedef struct {
  FieldElement X;
  FieldElement Y;
  FieldElement Z;
} ge_p2;

typedef struct {
  FieldElement X;
  FieldElement Y;
  FieldElement Z;
  FieldElement T;
} ge_p3;

typedef struct {
  FieldElement X;
  FieldElement Y;
  FieldElement Z;
  FieldElement T;
} ge_p1p1;

typedef struct {
  FieldElement yplusx;
  FieldElement yminusx;
  FieldElement xy2d;
} ge_precomp;

typedef struct {
  FieldElement YplusX;
  FieldElement YminusX;
  FieldElement Z;
  FieldElement T2d;
} ge_cached;

void ge_p1p1_to_p2(ge_p2 *r,const ge_p1p1 *p);
void ge_p1p1_to_p3(ge_p3 *r,const ge_p1p1 *p);
void ge_p2_dbl(ge_p1p1 *r,const ge_p2 *p);
void ge_p3_0(ge_p3 *h);
void ge_p3_dbl(ge_p1p1 *r,const ge_p3 *p);
void ge_p3_to_p2(ge_p2 *r,const ge_p3 *p);
void ge_precomp_0(ge_precomp *h);
void ge_madd(ge_p1p1 *r,const ge_p3 *p,const ge_precomp *q);
void ge_scalarmult_base(ge_p3 *h,const unsigned char *a);

} // namespace elligator

#endif
