// Copyright 2005, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>

#include "util.h"
#include "connections.h"
#include "../payload_server.h"

#include "file_steg.h"
#include "pngSteg.h"

#include "pngSteg.h"
#include <gtest/gtest.h>

using namespace std;


// Tests factorial of negative numbers.
TEST(pngStegTest, encode_decode) {
  // This test is named "Negative", and belongs to the "FactorialTest"
  // test case.

  ifstream png_test_cover("test1.png", ios::binary, ios::ate);
  ASSERT_TRUE(png_test_cover.is_open());
  
  //read the whole file
  size_t cover_len = png_test_cover.tellg();
  uint8_t* cover_payload = new uint8_t[cover_len];

  ASSERT_TRUE(cover_payload);

  png_test_cover.seekg (0, ios::beg);
  png_test.read (cover_payload, cover_len);
  png_test.close();

  
  uint8_t test_phrase[] = "There are 10 types of people in the world: those who understand binary, and those who don't.";
  size_t data_len = strlen(test_phrase)+1
  uint8_t recovered_phrase = new uint8_t[data_len];
  PNGSteg test_steg;

  ASSERT_TRUE(test_steg.capacity(cover_payload, cover_len) >= data_len);
  
  EXPECT_EQ(cover_len, test_steg.encode(test_phrase, data_len, cover_payload, cover_len));

  EXPECT_EQ(strlen(test_phrase)+1, test_steg.decode(cover_payload, cover_len, recovered_phrase));
  EXPECT_FALSE(memcmp(test_phrase,recovered_phrase, data_len));
}

