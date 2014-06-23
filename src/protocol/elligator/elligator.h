//
// This library is a derivative of agl's "ed25519/extra25519" go package
// distributed under the following license:
//
//   Copyright 2013 The Go Authors. All rights reserved.
//   Use of this source code is governed by a BSD-style
//   license that can be found in the LICENSE file.
//

#ifndef ELLIGATOR_ELLIGATOR_H__
#define ELLIGATOR_ELLIGATOR_H__

#include <cstddef>
#include <stdint.h>

namespace elligator {

const std::size_t PublicKeyLength = 32;
const std::size_t PrivateKeyLength = 32;
const std::size_t RepresentativeLength = 32;

typedef uint8_t PublicKey[PublicKeyLength];
typedef uint8_t PrivateKey[PrivateKeyLength];
typedef uint8_t Representative[RepresentativeLength];

bool ScalarBaseMult(PublicKey& publicKey,
                    Representative& representative,
                    const PrivateKey& privateKey);

void RepresentativeToPublicKey(PublicKey& publicKey,
                               const Representative& representative);

} // namespace elligator

#endif
