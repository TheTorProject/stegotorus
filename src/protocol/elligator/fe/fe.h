//
// This is the field element code taken from the ref10 ed25519 implementation
// provided in SUPERCOP.  Any porting errors are mine alone.
//

#ifndef ELLIGATOR_FE_FE_H__
#define ELLIGATOR_FE_FE_H__

#include <cstddef>
#include <stdint.h>

namespace elligator {

typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;
typedef int64_t crypto_int64;
typedef uint64_t crypto_uint64;

class FieldElement {
 public:
  static const size_t Size = 10;

  int32_t& operator[](std::size_t pos) {
    return h[pos];
  }
  const int32_t& operator[](std::size_t pos) const {
    return const_cast<int32_t&>(h[pos]);
  }

  void fromBytes(const unsigned char* s);
  void toBytes(unsigned char* s) const;

  void copy(const FieldElement f);

  void add(const FieldElement& f) {add(*this, f); }
  void add(const FieldElement& f,
           const FieldElement& g);

  void mul(const FieldElement& f) { mul(*this, f); }
  void mul(const FieldElement& f,
           const FieldElement& g);

  void sq() { sq(*this); }
  void sq(const FieldElement& f);

  void sq2(const FieldElement& f);

  void sub(const FieldElement& f,
           const FieldElement& g);

  void neg() {neg(*this); }
  void neg(const FieldElement& f);

  void invert() { invert(*this); }
  void invert(const FieldElement& z);

  void zero() {
    for (size_t i = 0; i < Size; i++) { h[i] = 0; }
  }

  void one() {
    zero();
    h[0] = 1;
  }

  int isnonzero() const;

  void cmov(const FieldElement& g, unsigned int b);

  int32_t h[FieldElement::Size];
};

int crypto_verify_32(const unsigned char *,const unsigned char *);

} // namespace elligator

#endif
