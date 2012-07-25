/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "unittest.h"
#include "../steg/payload_server.h"
#include "../steg/pdfSteg.h"

static void
test_pdf_add_remove_delimiters(void *)
{
  const char *data1 = "this is a test?? yes!";
  char data2[100];
  char data3[100];
  int dlen2, dlen3;
  bool end = false, escape = false;

  memset(data2, 0, sizeof data2);
  memset(data3, 0, sizeof data3);

  dlen2 = pdf_add_delimiter(data1, strlen(data1), data2, 100, '?', '.');
  tt_int_op(dlen2, ==, 25);
  tt_stn_op(data2, ==, "this is a test???? yes!?", 24);
  tt_char_op(data2[24], !=, '?');

  dlen3 = pdf_remove_delimiter(data2, dlen2, data3, 100, '?', &end, &escape);
  tt_int_op(dlen3, ==, 21);
  tt_str_op(data3, ==, data1);
  tt_bool_op(end, ==, true);
  tt_bool_op(escape, ==, false);

 end:;
}

static void
test_pdf_wrap_unwrap(void *)
{
  const char *pdf =
    "[PDFHDR][STUFFS1]1 0 obj <<\n/Length 12\n/Filter /FlateDecode\n>>\nstream\nABCDEFGHIJYY>>endstream\n[STUFF2][PDFTRAILER]";

  const char *const tests[] = {
    "12345",
    "123456789012",
    "12345678901",
    "1234567890?",
    0
  };

  char out[200];
  char orig[200];
  int i;
  size_t r1, r2;
  ssize_t rv;

  for (i = 0; tests[i]; i++) {
    memset(out, 0, sizeof out);
    memset(orig, 0, sizeof out);
    rv = pdf_wrap(tests[i], strlen(tests[i]),
                  pdf, strlen(pdf),
                  out, sizeof out);
    tt_int_op(rv, >, 0);
    r1 = rv;

    rv = pdf_unwrap(out, r1, orig, sizeof orig);
    tt_int_op(rv, >, 0);
    r2 = rv;
    tt_int_op(r2, ==, strlen(tests[i]));
    tt_stn_op(orig, ==, tests[i], r2);
  }

 end:;
}

#define T(name) \
  { #name, test_pdf_##name, 0, 0, 0 }

struct testcase_t pdf_tests[] = {
  T(add_remove_delimiters),
  T(wrap_unwrap),
  END_OF_TESTCASES
};
