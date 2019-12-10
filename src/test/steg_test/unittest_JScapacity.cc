/*
void testOffset2Alnum_skipJSPattern () {
  char s1[] = "for (i=0; i<10; i++) { print i; }";

  char s2[] = "***abcde*****";
  int d, i;

  printf("s1 = %s\n", s1);
  printf("s2 = %s\n", s2);


  d = offset2Alnum_(s1, strlen(s1));
  printf ("offset2Alnum_ for s1 = %d\n", d);
  d = offset2Alnum_(s2, strlen(s2));
  printf ("offset2Alnum_ for s2 = %d\n", d);

  i = skipJSPattern (s1, strlen(s1));
  printf ("skipJSPattern for s1 = %d\n", i);
  i = skipJSPattern (s2, strlen(s2));
  printf ("skipJSPattern for s2 = %d\n", i);
}


void testOffset2Hex () {
  int d;
  char s3[] = "for (bc=0; bc<10; bc++) { ad=2*bc+ad; }";
  printf("len(s3)=%d; s3 = |%s|\n", (int)strlen(s3), s3);

  d = offset2Alnum_(s3, strlen(s3));
  printf ("offset2Alnum_ for s3 = %d\n", d);
  d = offset2Hex(s3, strlen(s3), 0);
  printf ("offset2Hex for s3 = %d\n", d);

}


void testCapacityJS () {
  int d;
  char s4[] = "\r\n\r\n abc = abc + 1;";
  char s6[] = "\r\n\r\n <script type=\"text/javascript\">abc = abc + 1;</script>";

  printf("\nTest for CONTENT_JAVASCRIPT:\n");
  printf("len(s4)=%d; s4 = |%s|\n", (int)strlen(s4), s4);

  d = offset2Alnum_(s4, strlen(s4));
  printf ("offset2Alnum_ for s4 = %d\n", d);
  d = offset2Hex(s4, strlen(s4), 0);
  printf ("offset2Hex for s4 = %d\n", d);

  printf("capacityJS  (JS) returns %d\n", capacityJS(s4, strlen(s4), CONTENT_JAVASCRIPT));
  printf("capacityJS3 (JS) returns %d\n", capacityJS3(s4, strlen(s4), CONTENT_JAVASCRIPT));

  printf("\nTest for CONTENT_HTML_JAVASCRIPT:\n");
  printf("len(s6)=%d; s6 = |%s|\n", (int)strlen(s6), s6);

  d = offset2Alnum_(s6, strlen(s6));
  printf ("offset2Alnum_ for s6 = %d\n", d);
  d = offset2Hex(s6, strlen(s6), 0);
  printf ("offset2Hex for s6 = %d\n", d);

  printf("capacityJS  (HTML) returns %d\n", capacityJS(s6, strlen(s6), CONTENT_HTML_JAVASCRIPT));
  printf("capacityJS3 (HTML) returns %d\n", capacityJS3(s6, strlen(s6), CONTENT_HTML_JAVASCRIPT));
}
*/


/*****
int main() {
  char buf[HTTP_PAYLOAD_BUF_SIZE];
  memset(buf, 0, sizeof(buf));
  // test for TYPE_HTTP_REQUEST
  // load_payloads("../../traces/client.out");
  // int len = find_client_payload(buf, 10000, TYPE_HTTP_REQUEST);
  // printf("%s\n", buf);

  // test for TYPE_HTTP_RESPONSE
  // load_payloads("../../traces/server-cnn-nogzip.out");
  // load_payloads("../../traces/server-portals.out"); // ptype==1?

  // testOffset2Alnum_skipJSPattern();
  // testOffset2Hex();
  // testCapacityJS();
  
  load_payloads("../../traces/server.out");
  // int r;
  // r = find_server_payload(&buf, sizeof(buf), TYPE_HTTP_RESPONSE, HTTP_CONTENT_JAVASCRIPT);
  // if (r > 0) {
  //   printf("Available payload capablity %d\n", r);
  // }
  // return r;

  return 0;
}
 *****/
/**int testEncode(char *data, char *js, char *outBuf, unsigned int dlen, unsigned int jslen,
               unsigned int outBufLen, int testNum) {
  int r;

  printf ("***** Start of testEncode (%i) *****\n", testNum);
  printf ("Input:\n");
  printf ("data         = %s\n", data);
  printf ("data len     = %i\n", dlen);
  printf ("js           = %s\n", js);
  printf ("js len       = %i\n", jslen);
  r = encode (data, js, outBuf, dlen, jslen, outBufLen);
  if (r < 0) {
    printerr(r); 
  } else {
    printf ("\nOutput:\n");
    printf ("%i char of data embedded in outBuf\n", r);
    outBuf[jslen]    = '\0';
    printf ("outBuf       = %s\n", outBuf);
  }
  printf ("***** End of testEncode (%i) *****\n", testNum);
  return r;
}

int testDecode(char *inBuf, char *outBuf, unsigned int inBufSize, unsigned int dlen,
               unsigned int outBufSize, int testNum) {

  int r;

  printf ("***** Start of testDecode (%i) *****\n", testNum);
  printf ("Input:\n");
  printf ("inBuf       = %s\n", inBuf);
  printf ("inBuf size  = %i\n", inBufSize);
  printf ("data len    = %i\n", dlen);
  printf ("outBuf size = %i\n", outBufSize);
  r = decode(inBuf, outBuf, inBufSize, dlen, outBufSize);
  if (r < 0) {
    printerr(r);
  } else {
    printf ("\nOutput:\n");
    printf ("%i char of data recovered from inBuf (to outBuf)\n", r);
    outBuf[r] = '\0';
    printf ("outBuf   = %s\n", outBuf);
  }
  printf ("***** End of testDecode (%i) *****\n", testNum);
  return r;
}
p

int testEncode2(char *data, char *js, char *outBuf,
                unsigned int dlen, unsigned int jslen, unsigned int outBufLen,
                int mode, int testNum) {
  int r;
  // int fin;

  printf ("***** Start of testEncode2 (%i) *****\n", testNum);
  printf ("Input:\n");
  printf ("data         = %s\n", data);
  printf ("data len     = %i\n", dlen);
  printf ("js           = %s\n", js);
  printf ("js len       = %i\n", jslen);
  // r = encode2(data, js, outBuf, dlen, jslen, outBufLen, &fin);
  r = encodeHTTPBody(data, js, outBuf, dlen, jslen, outBufLen, mode);

  if (r < 0) {
    printerr(r);
  }
  else {
    printf ("\nOutput:\n");
    printf ("%i char of data embedded in outBuf\n", r);
    //    printf ("fin          = %d\n", fin);
    outBuf[jslen]    = '\0';
    printf ("outBuf       = %s\n", outBuf);

    if ((unsigned int) r < dlen) {
      printf ("Incomplete data encoding\n");
    }
  }
  printf ("***** End of testEncode (%i) *****\n", testNum);
  return r;
}




int testDecode2(char *inBuf, char *outBuf,
             unsigned int inBufSize, unsigned int outBufSize,
             int mode, int testNum) {
  int r;
  int fin;

  printf ("***** Start of testDecode2 (%i) *****\n", testNum);
  printf ("Input:\n");
  printf ("inBuf       = %s\n", inBuf);
  printf ("inBuf size  = %i\n", inBufSize);
  printf ("outBuf size = %i\n", outBufSize);
  r = decodeHTTPBody(inBuf, outBuf, inBufSize, outBufSize, &fin, mode);
  if (r < 0) {
    printerr(r);
  } else {
    printf ("\nOutput:\n");
    printf ("%i char of data recovered from inBuf (to outBuf)\n", r);
    outBuf[r] = '\0';
    printf ("outBuf   = %s\n", outBuf);
  }
  printf ("***** End of testDecode2 (%i) *****\n", testNum);
  return r;
}**/

/*****
      int
      main() {
      int jDataSize = 1000;
      char jData[jDataSize];
      int outDataBufSize = 1000;
      char outDataBuf[outDataBufSize];

      int r;
      // test case 1: data embedded in javascript
      r = testEncode2(data1, js1, jData, strlen(data1), strlen(js1), jDataSize,
      CONTENT_JAVASCRIPT, 1);
      if (r > 0) { testDecode2(jData, outDataBuf, strlen(js1), outDataBufSize, CONTENT_JAVASCRIPT, 1); }

      // test case 4: data embedded in one script type javascript
      r = testEncode2(data1, js4, jData, strlen(data1), strlen(js4), jDataSize,
      CONTENT_HTML_JAVASCRIPT, 4);
      if (r > 0) { testDecode2(jData, outDataBuf, strlen(js4), outDataBufSize, CONTENT_HTML_JAVASCRIPT, 4); }

      // test case 5: data embedded in one script type javascript
      r = testEncode2(data1, js5, jData, strlen(data1), strlen(js5), jDataSize,
      CONTENT_HTML_JAVASCRIPT, 5);
      if (r > 0) { testDecode2(jData, outDataBuf, strlen(js5), outDataBufSize, CONTENT_HTML_JAVASCRIPT, 5); }


      return 0;
      }
*****/

/*****
      int
      main() {
      int jDataSize = 1000;
      char jData[jDataSize];
      int jDataSmallSize = 5;
      char jDataSmall[jDataSmallSize];

      int outDataBufSize = 1000;
      char outDataBuf[outDataBufSize];
      int outDataSmallSize = 5;
      char outDataSmall[outDataSmallSize];

      int r;

      // test case 1: data embedded in javascript
      r = testEncode(data1, js1, jData, strlen(data1), strlen(js1), jDataSize, 1);
      if (r > 0) { testDecode(jData, outDataBuf, strlen(js1), r, outDataBufSize, 1); }

      // test case 2: data embedded in javascript
      r = testEncode(data1, js2, jData, strlen(data1), strlen(js2), jDataSize, 2);
      if (r > 0) { testDecode(jData, outDataBuf, strlen(js2), r, outDataBufSize, 2); }

      // test case 3: data partially embedded in javascript; num of hex char in js < data len
      r = testEncode(data1, js3, jData, strlen(data1), strlen(js3), jDataSize, 3);
      if (r > 0) { testDecode(jData, outDataBuf, strlen(js3), r, outDataBufSize, 3); }

      // test case 4: data embedded in javascript; larger data
      r = testEncode(data2, js1, jData, strlen(data2), strlen(js1), jDataSize, 4);
      if (r > 0) { testDecode(jData, outDataBuf, strlen(js1), r, outDataBufSize, 4); }

      // test case 5 (for encode): err for non-hex data
      testEncode(nonhexstr, js1, jData, strlen(nonhexstr), strlen(js1), jDataSize, 5);

      // test case 6 (for encode): err for small output buf
      testEncode(data1, js1, jDataSmall, strlen(data1), strlen(js1), jDataSmallSize, 6);

      // test case 7 (for decode): err for small output buf
      r = testEncode(data1, js1, jData, strlen(data1), strlen(js1), jDataSize, 7);
      if (r > 0) { testDecode(jData, outDataSmall, strlen(js1), r, outDataSmallSize, 7); }
      }
*****/
