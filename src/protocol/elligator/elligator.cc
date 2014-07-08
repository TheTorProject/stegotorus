//
// This library is a derivative of agl's "ed25519/extra25519" go package
// distributed under the following license:
//
//   Copyright 2013 The Go Authors. All rights reserved.
//   Use of this source code is governed by a BSD-style
//   license that can be found in the LICENSE file.
//

#include "elligator/elligator.h"
#include "elligator/fe/fe.h"
#include "elligator/ge/ge.h"

#include <cstring>

namespace elligator {

void* (*volatile memset_volatile)(void *, int, size_t) = std::memset;

static const FieldElement A = {{
  486662, 0, 0, 0, 0, 0, 0, 0, 0, 0
}};

static const FieldElement SqrtM1 = {{
  -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654,
  326686, 11406482,
}};

// sqrtMinusA is sqrt(-486662)
static const FieldElement sqrtMinusA = {{
  12222970, 8312128, 11511410, -9067497, 15300785, 241793, -25456130, -14121551,
  12187136, -3972024
}};

// sqrtMinusHalf is sqrt(-1/2)
static const FieldElement sqrtMinusHalf = {{
  -17256545, 3971863, 28865457, -1750208, 27359696, -16640980, 12573105,
  1002827, -163343, 11073975,
}};

// halfQMinus1Bytes is (2^255-20)/2 expressed in little endian form.
static const uint8_t halfQMinus1Bytes[32] = {
  0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
};

// feBytesLess returns one if a <= b and zero otherwise.
static unsigned int feBytesLE(const uint8_t (&a)[32],
                              const uint8_t (&b)[32]) {
  int32_t equalSoFar = -1;  /* equalSoFar := int32(-1) */
  int32_t greater = 0;      /* greater := int32(0) */

  for (size_t i = 31; i < 32; i--) {
    int32_t x = static_cast<int32_t>(a[i]); /* x := int32(a[i]) */
    int32_t y = static_cast<int32_t>(b[i]); /* y := int32(b[i]) */

    greater = (~equalSoFar & greater) | (equalSoFar & ((x - y) >> 31));
    equalSoFar = equalSoFar & (((x ^ y) - 1) >> 31);
  }

  return static_cast<unsigned int>(~equalSoFar & 1 & greater);
}

// q58 calculates out = z^((p-5)/8).
static void q58(FieldElement& out,
                const FieldElement& z) {
  FieldElement t1, t2, t3;  /* var t1, t2, t3 edwards25519.FieldElement */
  int i;                    /* var i int */

  t1.sq(z);           /* edwards25519.FeSquare(&t1, z) // 2^1 */
  t1.mul(z);          /* edwards25519.FeMul(&t1, &t1, z) // 2^1 + 2^0 */
  t1.sq();            /* edwards25519.FeSquare(&t1, &t1) // 2^2 + 2^1 */
  t2.sq(t1);          /* edwards25519.FeSquare(&t2, &t1) // 2^3 + 2^2 */
  t2.sq();            /* edwards25519.FeSquare(&t2, &t2) // 2^4 + 2^3 */
  t2.mul(t1);         /* edwards25519.FeMul(&t2, &t2, &t1) // 4,3,2,1 */
  t1.mul(t2, z);      /* edwards25519.FeMul(&t1, &t2, z) // 4..0 */
  t2.sq(t1);          /* edwards25519.FeSquare(&t2, &t1) // 5..1 */
  for (i = 1; i < 5; i++) { // 9,8,7,6,5
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t1.mul(t2);         /* edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0 */
  t2.sq(t1);          /* edwards25519.FeSquare(&t2, &t1) // 10..1 */
  for (i = 1; i < 10; i++) { // 19..10 
    t2.sq();          /*edwards25519.FeSquare(&t2, &t2) */
  }
  t2.mul(t1);         /* edwards25519.FeMul(&t2, &t2, &t1) // 19..0 */
  t3.sq(t2);          /* edwards25519.FeSquare(&t3, &t2) // 20..1 */
  for (i = 1; i < 20; i++) { // 39..20
    t3.sq();          /* edwards25519.FeSquare(&t3, &t3) */
  }
  t2.mul(t3);         /* edwards25519.FeMul(&t2, &t3, &t2) // 39..0 */
  t2.sq();            /* edwards25519.FeSquare(&t2, &t2) // 40..1 */
  for (i = 1; i < 10; i++) { // 49..10
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t1.mul(t2);         /* edwards25519.FeMul(&t1, &t2, &t1) // 49..0 */
  t2.sq(t1);          /* edwards25519.FeSquare(&t2, &t1) // 50..1 */
  for (i = 1; i < 50; i++) { // 99..50
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t2.mul(t1);         /* edwards25519.FeMul(&t2, &t2, &t1) // 99..0 */
  t3.sq(t2);          /* edwards25519.FeSquare(&t3, &t2) // 100..1 */
  for (i = 1; i < 100; i++) { // 199..100
    t3.sq();          /* edwards25519.FeSquare(&t3, &t3) */
  }
  t2.mul(t3);         /* edwards25519.FeMul(&t2, &t3, &t2) // 199..0 */
  t2.sq();            /* edwards25519.FeSquare(&t2, &t2) // 200..1 */
  for (i = 1; i < 50; i++) { // 249..50
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t1.mul(t2);         /* edwards25519.FeMul(&t1, &t2, &t1) // 249..0 */
  t1.sq();            /* edwards25519.FeSquare(&t1, &t1) // 250..1 */
  t1.sq();            /* edwards25519.FeSquare(&t1, &t1) // 251..2 */
  out.mul(t1, z);     /* edwards25519.FeMul(out, &t1, z) // 251..2,0 */
}

// chi calculates out = z^((p-1)/2). The result is either 1, 0, or -1 depending
// on whether z is a non-zero square, zero, or a non-square.
static void chi(FieldElement& out, const FieldElement& z) {
  FieldElement t0, t1, t2, t3;
  int i;

  t0.sq(z);         /* edwards25519.FeSquare(&t0, z) // 2^1 */
  t1.mul(t0, z);    /* edwards25519.FeMul(&t1, &t0, z) // 2^1 + 2^0 */
  t0.sq(t1);        /* edwards25519.FeSquare(&t0, &t1) // 2^2 + 2^1 */
  t2.sq(t0);        /* edwards25519.FeSquare(&t2, &t0) // 2^3 + 2^2 */
  t2.sq();          /* edwards25519.FeSquare(&t2, &t2) // 4,3 */
  t2.mul(t0);       /* edwards25519.FeMul(&t2, &t2, &t0) // 4,3,2,1 */
  t1.mul(t2, z);    /* edwards25519.FeMul(&t1, &t2, z) // 4..0 */
  t2.sq(t1);        /* edwards25519.FeSquare(&t2, &t1) // 5..1 */
  for (i = 1; i < 5; i++) { // 9,8,7,6,5
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t1.mul(t2);       /* edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0 */
  t2.sq(t1);        /* edwards25519.FeSquare(&t2, &t1) // 10..1 */
  for (i = 1; i < 10; i++) { // 19..10
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t2.mul(t1);       /* edwards25519.FeMul(&t2, &t2, &t1) // 19..0 */
  t3.sq(t2);        /* edwards25519.FeSquare(&t3, &t2) // 20..1 */
  for (i = 1; i < 20; i++) { // 39..20
    t3.sq();          /* edwards25519.FeSquare(&t3, &t3) */
  }
  t2.mul(t3);       /* edwards25519.FeMul(&t2, &t3, &t2) // 39..0 */
  t2.sq();          /* edwards25519.FeSquare(&t2, &t2) // 40..1 */
  for (i = 1; i < 10; i++) { // 49..10
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t1.mul(t2);       /* edwards25519.FeMul(&t1, &t2, &t1) // 49..0 */
  t2.sq(t1);        /* edwards25519.FeSquare(&t2, &t1) // 50..1 */
  for (i = 1; i < 50; i++) { // 99..50
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t2.mul(t1);       /* edwards25519.FeMul(&t2, &t2, &t1) // 99..0 */
  t3.sq(t2);        /* edwards25519.FeSquare(&t3, &t2) // 100..1 */
  for (i = 1; i < 100; i++) { // 199..100
    t3.sq();          /*edwards25519.FeSquare(&t3, &t3) */
  }
  t2.mul(t3);       /* edwards25519.FeMul(&t2, &t3, &t2) // 199..0 */
  t2.sq();          /* edwards25519.FeSquare(&t2, &t2) // 200..1 */
  for (i = 1; i < 50; i++) { // 249..50
    t2.sq();          /* edwards25519.FeSquare(&t2, &t2) */
  }
  t1.mul(t2);       /* edwards25519.FeMul(&t1, &t2, &t1) // 249..0 */
  t1.sq();          /* edwards25519.FeSquare(&t1, &t1) // 250..1 */
  for (i = 1; i < 4; i++) { // 253..4
    t1.sq();          /* edwards25519.FeSquare(&t1, &t1) */
  }
  out.mul(t1, t0);  /* edwards25519.FeMul(out, &t1, &t0) // 253..4,2,1 */
}

// ScalarBaseMult computes a curve25519 public key from a private key and also
// a uniform representative for that public key. Note that this function will
// fail and return false for about half of private keys.
// See http://elligator.cr.yp.to/elligator-20130828.pdf.
bool ScalarBaseMult(PublicKey& publicKey,
                    Representative& representative,
                    const PrivateKey& privateKey) {
  uint8_t maskedPrivateKey[PrivateKeyLength];
  std::memcpy(maskedPrivateKey, privateKey, sizeof(maskedPrivateKey)); /* copy(maskedPrivateKey[:], privateKey[:]) */
  maskedPrivateKey[0] &= 248;   /* maskedPrivateKey[0] &= 248 */
  maskedPrivateKey[31] &= 127;  /* maskedPrivateKey[31] &= 127 */
  maskedPrivateKey[31] |= 64;   /* maskedPrivateKey[31] |= 64 */

  ge_p3 AA;           /* var A edwards25519.ExtendedGroupElement */
  ge_scalarmult_base(&AA, maskedPrivateKey); /* edwards25519.GeScalarMultBase(&A, &maskedPrivateKey) */
  memset_volatile(maskedPrivateKey, 0, sizeof(maskedPrivateKey));

  FieldElement inv1;
  inv1.sub(AA.Z, AA.Y); /* edwards25519.FeSub(&inv1, &A.Z, &A.Y) */
  inv1.mul(AA.X);     /* edwards25519.FeMul(&inv1, &inv1, &A.X) */
  inv1.invert();      /* edwards25519.FeInvert(&inv1, &inv1) */

  FieldElement t0, u;
  u.mul(inv1, AA.X);  /* edwards25519.FeMul(&u, &inv1, &A.X) */
  t0.add(AA.Y, AA.Z); /* edwards25519.FeAdd(&t0, &A.Y, &A.Z) */
  u.mul(t0);          /* edwards25519.FeMul(&u, &u, &t0) */

  FieldElement v;
  v.mul(t0, inv1);    /* edwards25519.FeMul(&v, &t0, &inv1) */
  v.mul(AA.Z);        /* edwards25519.FeMul(&v, &v, &A.Z) */
  v.mul(sqrtMinusA);  /* edwards25519.FeMul(&v, &v, &sqrtMinusA) */

  FieldElement b;
  b.add(u, A);        /* edwards25519.FeAdd(&b, &u, &edwards25519.A) */

  FieldElement c, b3, b8;
  b3.sq(b);           /* edwards25519.FeSquare(&b3, &b) // 2 */
  b3.mul(b);          /* edwards25519.FeMul(&b3, &b3, &b) // 3 */
  c.sq(b3);           /* edwards25519.FeSquare(&c, &b3) // 6 */
  c.mul(b);           /* edwards25519.FeMul(&c, &c, &b) // 7 */
  b8.mul(c, b);       /* edwards25519.FeMul(&b8, &c, &b) // 8 */
  c.mul(u);           /* edwards25519.FeMul(&c, &c, &u) */
  q58(c, c);          /* q58(&c, &c) */

  FieldElement chi;
  chi.sq(c);          /* edwards25519.FeSquare(&chi, &c) */
  chi.sq();           /* edwards25519.FeSquare(&chi, &chi) */

  t0.sq(u);           /* edwards25519.FeSquare(&t0, &u) */
  chi.mul(t0);        /* edwards25519.FeMul(&chi, &chi, &t0) */

  t0.sq(b);           /* edwards25519.FeSquare(&t0, &b) // 2 */
  t0.mul(b);          /* edwards25519.FeMul(&t0, &t0, &b) // 3 */
  t0.sq();            /* edwards25519.FeSquare(&t0, &t0) // 6 */
  t0.mul(b);          /* edwards25519.FeMul(&t0, &t0, &b) // 7 */
  t0.sq();            /* edwards25519.FeSquare(&t0, &t0) // 14 */
  chi.mul(t0);        /* edwards25519.FeMul(&chi, &chi, &t0) */
  chi.neg();          /* edwards25519.FeNeg(&chi, &chi) */

  uint8_t chiBytes[32];
  chi.toBytes(chiBytes);  /*edwards25519.FeToBytes(&chiBytes, &chi) */
  // chi[1] is either 0 or 0xff
  if (chiBytes[1] == 0xff) {
    return false;
  }

  // Calculate r1 = sqrt(-u/(2*(u+A)))
  FieldElement r1;
  r1.mul(c, u);       /* edwards25519.FeMul(&r1, &c, &u) */
  r1.mul(b3);         /* edwards25519.FeMul(&r1, &r1, &b3) */
  r1.mul(sqrtMinusHalf);  /* edwards25519.FeMul(&r1, &r1, &sqrtMinusHalf) */

  FieldElement maybeSqrtM1;
  t0.sq(r1);          /* edwards25519.FeSquare(&t0, &r1) */
  t0.mul(b);          /* edwards25519.FeMul(&t0, &t0, &b) */
  t0.add(t0);         /* edwards25519.FeAdd(&t0, &t0, &t0) */
  t0.add(u);          /* edwards25519.FeAdd(&t0, &t0, &u) */

  maybeSqrtM1.one();  /* edwards25519.FeOne(&maybeSqrtM1) */
  maybeSqrtM1.cmov(SqrtM1, t0.isnonzero()); /* edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0)) */
  r1.mul(maybeSqrtM1);/* edwards25519.FeMul(&r1, &r1, &maybeSqrtM1) */

  // Calculate r = sqrt(-(u+A)/(2u))
  FieldElement r;
  t0.sq(c);           /* edwards25519.FeSquare(&t0, &c) // 2 */
  t0.mul(c);          /* edwards25519.FeMul(&t0, &t0, &c) // 3 */
  t0.sq();            /* edwards25519.FeSquare(&t0, &t0) // 6 */
  r.mul(t0, c);       /* edwards25519.FeMul(&r, &t0, &c) // 7 */

  t0.sq(u);           /* edwards25519.FeSquare(&t0, &u) // 2 */
  t0.mul(u);          /* edwards25519.FeMul(&t0, &t0, &u) // 3 */
  r.mul(t0);          /* edwards25519.FeMul(&r, &r, &t0) */

  t0.sq(b8);          /* edwards25519.FeSquare(&t0, &b8) // 16 */
  t0.mul(b8);         /* edwards25519.FeMul(&t0, &t0, &b8) // 24 */
  t0.mul(b);          /* edwards25519.FeMul(&t0, &t0, &b) // 25 */
  r.mul(t0);          /* edwards25519.FeMul(&r, &r, &t0) */
  r.mul(sqrtMinusHalf); /* edwards25519.FeMul(&r, &r, &sqrtMinusHalf) */

  t0.sq(r);           /* edwards25519.FeSquare(&t0, &r) */
  t0.mul(u);          /* edwards25519.FeMul(&t0, &t0, &u) */
  t0.add(t0);         /* edwards25519.FeAdd(&t0, &t0, &t0) */
  t0.add(b);          /* edwards25519.FeAdd(&t0, &t0, &b) */
  maybeSqrtM1.one();  /* edwards25519.FeOne(&maybeSqrtM1) */
  maybeSqrtM1.cmov(SqrtM1, t0.isnonzero()); /* edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0)) */
  r.mul(maybeSqrtM1); /* edwards25519.FeMul(&r, &r, &maybeSqrtM1) */

  uint8_t vBytes[32];
  v.toBytes(vBytes);  /* edwards25519.FeToBytes(&vBytes, &v) */
  unsigned int vInSquareRootImage = feBytesLE(vBytes, halfQMinus1Bytes); /* vInSquareRootImage := feBytesLE(&vBytes, &halfQMinus1Bytes) */
  r.cmov(r1, vInSquareRootImage); /* edwards25519.FeCMove(&r, &r1, vInSquareRootImage) */

  u.toBytes(publicKey); /* edwards25519.FeToBytes(publicKey, &u) */
  r.toBytes(representative);  /* edwards25519.FeToBytes(representative, &r) */
  return true;
}

// RepresentativeToPublicKey converts a uniform representative value for a
// curve25519 public key, as produced by ScalarBaseMult, to a curve25519 public
// key.
void RepresentativeToPublicKey(PublicKey& publicKey,
                               const Representative& representative) {
  FieldElement rr2, v, e;
  rr2.fromBytes(representative);  /* edwards25519.FeFromBytes(&rr2, representative) */

  rr2.sq2(rr2);     /* edwards25519.FeSquare2(&rr2, &rr2) */
  rr2[0]++;         /* rr2[0]++ */
  rr2.invert();     /* edwards25519.FeInvert(&rr2, &rr2) */
  v.mul(A, rr2);    /* edwards25519.FeMul(&v, &edwards25519.A, &rr2) */
  v.neg();          /* edwards25519.FeNeg(&v, &v) */

  FieldElement v2, v3;
  v2.sq(v);         /* edwards25519.FeSquare(&v2, &v) */
  v3.mul(v, v2);    /* edwards25519.FeMul(&v3, &v, &v2) */
  e.add(v3, v);     /* edwards25519.FeAdd(&e, &v3, &v) */
  v2.mul(A);        /* edwards25519.FeMul(&v2, &v2, &edwards25519.A) */
  e.add(v2);        /* edwards25519.FeAdd(&e, &v2, &e) */
  chi(e, e);        /* chi(&e, &e) */
  uint8_t eBytes[32];
  e.toBytes(eBytes);  /* edwards25519.FeToBytes(&eBytes, &e) */
  // eBytes[1] is either 0 (for e = 1) or 0xff (for e = -1)
  unsigned int eIsMinus1 = eBytes[1] & 1;
  FieldElement negV;
  negV.neg(v);      /* edwards25519.FeNeg(&negV, &v) */
  v.cmov(negV, eIsMinus1);  /* edwards25519.FeCMove(&v, &negV, eIsMinus1) */

  v2.zero();              /* edwards25519.FeZero(&v2) */
  v2.cmov(A, eIsMinus1);  /* edwards25519.FeCMove(&v2, &edwards25519.A, eIsMinus1) */
  v.sub(v, v2);           /* edwards25519.FeSub(&v, &v, &v2) */

  v.toBytes(publicKey); /* edwards25519.FeToBytes(publicKey, &v) */
}

} //namespace elligator
