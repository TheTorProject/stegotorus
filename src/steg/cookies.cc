
#include "cookies.h"

int unwrap_cookie(unsigned char* inbuf, unsigned char* outbuf, int buflen) {
  int i,j;
  j = 0;

  for (i=0; i < buflen; i++) {
    char c  = inbuf[i];

    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
      outbuf[j++] = c; 
  }

  return j;

}






/* valid cookie characters: anything between between 33 and 126, with the exception of "=" and ';'*/
/* writes a line of the form XXXX=YYYYY of length cookielen to outbuf, outbuf length >= cookielen */
/* returns data consumed if success.  datalen assumed to be greater than cookielen*/


int gen_one_cookie(unsigned char* outbuf, int cookielen, unsigned char* data, int datalen) {
  int sofar = 0;
  unsigned char c;
  int namelen, vlen;
  int data_consumed = 0;

  if (cookielen < 4)
    return -1;



  if (cookielen > 13)
    namelen = rand() % 10 + 1;
  else 
    namelen = rand() % (cookielen - 3) + 1;

  vlen = cookielen - namelen;



  while (sofar < namelen) {
    c = rand() % (127 - 33) + 33;
    if (c == '=' || c == ';' || c == '`' || c == '\'' || c == '%' || c == '+' || c == '{' || c == '}' ||
	c == '<' || c == '>' || c == '?' || c == '#')
      continue;

    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (rand () % 4 != 0)) {
      if (data_consumed < datalen) 
	outbuf[sofar++] = data[data_consumed++];
    }
    else
      outbuf[sofar++] = c;
  }


  outbuf[sofar++] = '=';


  while (sofar < cookielen) {
    c = rand() % (127 - 33) + 33;
    if (c == '=' || c == ';' || c == '`' || c == '\'' || c == '%' || c == '+' || c == '{' || c == '}' ||
	c == '<' || c == '>' || c == '?' || c == '#')
      continue;



    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (rand() % 4 != 0)) {
      if (data_consumed < datalen) 
	outbuf[sofar++] = data[data_consumed++];
    }
    else
      outbuf[sofar++] = c;
  }


  
  return data_consumed;

}




/* dummy version for testing */
int gen_one_cookie2(unsigned char* outbuf, int cookielen, unsigned char* data, int datalen) {
  int i;

  if (cookielen < 4)
    return -1;

  if (datalen >= cookielen) {
    memcpy(outbuf, data, cookielen);
    return cookielen;
  }

  memcpy(outbuf, data, datalen);
  for (i=datalen; i < cookielen; i++)
    outbuf[i] = '+';

  return datalen;

}

/* returns data consumed */
int gen_cookie_field(unsigned char* outbuf, int total_cookie_len, unsigned char* data, int datalen) {
  int rem_cookie_len = total_cookie_len;
  int consumed = 0;


  if (total_cookie_len < 4) {
    fprintf(stderr, "error: cookie length too small\n");
    return -1;
  }

  while (rem_cookie_len > 4) {
    int cookielen = 4 + rand() % (rem_cookie_len - 3);

    int cnt =  gen_one_cookie(outbuf, cookielen, data + consumed, datalen - consumed);

    if (cnt < 0) {
      fprintf(stderr, "error: couldn't create cookie %d\n", cnt);
      return cnt;
    }



    consumed += cnt;
    //    fprintf(stderr, "cnt = %d %d %d; consumed = %d\n", cnt, rem_cookie_len, cookielen, consumed);
    rem_cookie_len = rem_cookie_len - cookielen;
    outbuf += cookielen;


 
   if (rem_cookie_len == 0) {
      break;
    }
    else if (rem_cookie_len <= 5) {
      int i = 0;
      if ((consumed < datalen) && (consumed % 2 == 1)) {
	outbuf[0] = data[consumed];
	consumed++;
	outbuf++;
	rem_cookie_len--;
      }

      for (i=0; i < rem_cookie_len; i++) 
	outbuf[i] = "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ"[rand() % 40];
      
      return consumed;
    }
    
    
    outbuf[0] = ';';
    outbuf++;
    rem_cookie_len--;
  }


  if (consumed % 2 == 1) {
    if ((outbuf[-1] >= '0' && outbuf[-1] <= '9') || (outbuf[-1] >= 'a' && outbuf[-1] <= 'f')) {
      outbuf[-1] = '*';
      consumed--;
    }
    else {
      outbuf[-1] = data[consumed];
      consumed++;
    }	  
  }


  return consumed;
}


/* dummy version for testing */
int gen_cookie_field2(unsigned char* outbuf, int total_cookie_len, unsigned char* data, int datalen) {
  int i;
  if (datalen >= total_cookie_len) {
    memcpy(outbuf, data, total_cookie_len);
    return total_cookie_len;
  }

  memcpy(outbuf, data, datalen);
  for (i=datalen; i < total_cookie_len; i++)
    outbuf[i] = '*';

  return datalen;
}




/*

int main () {
  char outbuf[200];
  char data[52] = "1a239023820389023802380389abc2322132321932847203aedf";
  char data2[200];
  //  srand(time(NULL));
  srand (20);



  int i=0;

  for (i=0; i < 1000000; i++) {
    int cookielen = rand()%50 + 5;
    bzero(outbuf, sizeof(outbuf));
    int len = gen_cookie_field(outbuf, cookielen, data, sizeof(data));
    //    printf("len = %d cookie = %s %d\n", len, outbuf, cookielen);
    bzero(data2, sizeof(data2));
    int len2 = unwrap_cookie(outbuf, data2, cookielen);
    //    printf("unwrapped datalen = %d data = %s\n", len, data2);

    if (len != len2)
      printf("hello %d\n", i);
  }
  



}

*/


