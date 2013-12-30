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
#include <string>
#include <boost/filesystem.hpp>

#include <event2/buffer.h>

#include "util.h"
#include "connections.h"
#include "util.h"
#include "crypt.h"
#include "curl_util.h"

#include "payload_server.h"

#include "file_steg.h"
#include "pngSteg.h"
#include "jpgSteg.h"
#include "gifSteg.h"

#include "payload_scraper.h"

#include <gtest/gtest.h>

using namespace std;
using namespace boost::filesystem;

class PayloadScraperTest : public testing::Test {
 protected:
  friend PayloadScraper;
  ssize_t cover_len;
  uint8_t* cover_payload;

  char* short_message;
  char* long_message;

  void read_cover(const char* cover_file_name) {
    ifstream test_cover(cover_file_name, ios::binary | ios::ate);
    ASSERT_TRUE(test_cover.is_open());
  
   //read the whole file
   cover_len = test_cover.tellg();
   cover_payload = new uint8_t[cover_len];

   ASSERT_TRUE(cover_payload);

   test_cover.seekg(0, ios::beg);
   test_cover.read((char*)cover_payload, cover_len);
   test_cover.close();
  }

  void encode_decode(const char* cover_file_name, const char* test_phrase, FileStegMod* test_steg_mod) {

    read_cover(cover_file_name);

    ssize_t data_len = strlen(test_phrase)+1;
    uint8_t recovered_phrase[FileStegMod::c_MAX_MSG_BUF_SIZE];

    ASSERT_TRUE(test_steg_mod->headless_capacity((char*)cover_payload, cover_len) >= data_len);
    
    EXPECT_EQ(cover_len, test_steg_mod->encode((uint8_t*)test_phrase, data_len, cover_payload, cover_len));
    
    EXPECT_EQ((signed)(strlen(test_phrase)+1), test_steg_mod->decode(cover_payload, cover_len, recovered_phrase));
   EXPECT_FALSE(memcmp(test_phrase,recovered_phrase, data_len));
   //  cout << test_phrase << endl;
   //  cout << recovered_phrase << endl;
  }

  virtual void SetUp()
  {

    char local_short[] = "There are 10 types of people in the world: those who understand binary, and those who don't.";

    char local_long[] = "Au jour finissant de cinq heures dont l'ombre obscurcit le vaste \
appartement de l'avenue de Messine, c'est mélancolique, ce désordre     \
qui survit à la fête nuptiale. Dans les salons aux meubles épars, que   \
tout à l'heure animait la rumeur d'une foule parée, et où flotte la \
poussière des tapis foulés longuement, vont se flétrissant les gerbes \
de lilas, de lis, de tubéreuses, blanches fleurs d'hyménée ennuagées \
de tulle. Et leurs parfums violents se font âcres en s'exaspérant de \
la chaleur lourde qui épaissit l'air.";

    short_message = new char[strlen(local_short)+1];
    long_message = new char[strlen(local_long)+1];

    strcpy(short_message, local_short);
    strcpy(long_message, local_long);
    
    cover_payload = NULL;

  }

  virtual void TearDown()
  {
    delete short_message;
    delete long_message;
    delete cover_payload;
  }

};

//GIF not found
TEST_F(PayloadScraperTest, nonexistance_capacity) {
  steg_type gif_test_steg;

  gif_test_steg.type = HTTP_CONTENT_GIF; gif_test_steg.extension = ".gif"; gif_test_steg.capacity_function = GIFSteg::static_capacity; //Temp measur
  PayloadScraper test_scraper("/tmp/test.txt", "127.0.0.1");
  
  pair<unsigned long, unsigned long> result = test_scraper.compute_capacity("mit.edu/doesntexist.gif", &gif_test_steg, true);
  EXPECT_TRUE(result.first == 0 && result.second  == 0 );

}

