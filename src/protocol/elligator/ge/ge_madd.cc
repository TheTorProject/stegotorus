//
// ge_madd.cc - SUPERCOP ed25519-ref10 ge_madd.c
//

#include "elligator/ge/ge.h"

namespace elligator {

/*
r = p + q
*/

void ge_madd(ge_p1p1 *r,const ge_p3 *p,const ge_precomp *q)
{
  FieldElement t0;

  /* qhasm: YpX1 = Y1+X1 */
  /* asm 1: fe_add(>YpX1=fe#1,<Y1=fe#12,<X1=fe#11); */
  /* asm 2: fe_add(>YpX1=r->X,<Y1=p->Y,<X1=p->X); */
  r->X.add(p->Y,p->X);

  /* qhasm: YmX1 = Y1-X1 */
  /* asm 1: fe_sub(>YmX1=fe#2,<Y1=fe#12,<X1=fe#11); */
  /* asm 2: fe_sub(>YmX1=r->Y,<Y1=p->Y,<X1=p->X); */
  r->Y.sub(p->Y,p->X);

  /* qhasm: A = YpX1*ypx2 */
  /* asm 1: fe_mul(>A=fe#3,<YpX1=fe#1,<ypx2=fe#15); */
  /* asm 2: fe_mul(>A=r->Z,<YpX1=r->X,<ypx2=q->yplusx); */
  r->Z.mul(r->X,q->yplusx);

  /* qhasm: B = YmX1*ymx2 */
  /* asm 1: fe_mul(>B=fe#2,<YmX1=fe#2,<ymx2=fe#16); */
  /* asm 2: fe_mul(>B=r->Y,<YmX1=r->Y,<ymx2=q->yminusx); */
  r->Y.mul(q->yminusx);

  /* qhasm: C = xy2d2*T1 */
  /* asm 1: fe_mul(>C=fe#4,<xy2d2=fe#17,<T1=fe#14); */
  /* asm 2: fe_mul(>C=r->T,<xy2d2=q->xy2d,<T1=p->T); */
  r->T.mul(q->xy2d,p->T);

  /* qhasm: D = 2*Z1 */
  /* asm 1: fe_add(>D=fe#5,<Z1=fe#13,<Z1=fe#13); */
  /* asm 2: fe_add(>D=t0,<Z1=p->Z,<Z1=p->Z); */
  t0.add(p->Z,p->Z);

  /* qhasm: X3 = A-B */
  /* asm 1: fe_sub(>X3=fe#1,<A=fe#3,<B=fe#2); */
  /* asm 2: fe_sub(>X3=r->X,<A=r->Z,<B=r->Y); */
  r->X.sub(r->Z,r->Y);

  /* qhasm: Y3 = A+B */
  /* asm 1: fe_add(>Y3=fe#2,<A=fe#3,<B=fe#2); */
  /* asm 2: fe_add(>Y3=r->Y,<A=r->Z,<B=r->Y); */
  r->Y.add(r->Z);

  /* qhasm: Z3 = D+C */
  /* asm 1: fe_add(>Z3=fe#3,<D=fe#5,<C=fe#4); */
  /* asm 2: fe_add(>Z3=r->Z,<D=t0,<C=r->T); */
  r->Z.add(t0,r->T);

  /* qhasm: T3 = D-C */
  /* asm 1: fe_sub(>T3=fe#4,<D=fe#5,<C=fe#4); */
  /* asm 2: fe_sub(>T3=r->T,<D=t0,<C=r->T); */
  r->T.sub(t0,r->T);
}

} // namespace elligator
