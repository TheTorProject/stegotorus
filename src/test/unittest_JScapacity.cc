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
  char buf[HTTP_MSG_BUF_SIZE];
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
