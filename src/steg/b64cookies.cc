
#include "b64cookies.h"
#include <string.h>

int unwrap_b64_cookie(char* inbuf, char* outbuf, int buflen) {
  int i,j;
  j = 0;

  for (i=0; i < buflen; i++) {
    char c  = inbuf[i];

    if (c != ' ' && c != ';' && c != '=')
      outbuf[j++] = c; 
  }

  return j;

}





int gen_one_b64cookie(char* outbuf, int& cookielen, char* data, int datalen) {
  int sofar = 0;
  int namelen;
  int data_consumed = 0;

  cookielen = 4 + rand() % (datalen - 3);
  
  if (cookielen > 13)
    namelen = rand() % 10 + 1;
  else 
    namelen = rand() % (cookielen - 3) + 1;

  
  while (sofar < namelen) {
    outbuf[sofar++] = data[data_consumed++];
  }


  outbuf[sofar++] = '=';

  while (sofar < cookielen) {
    outbuf[sofar++] = data[data_consumed++];
  }
  
  return data_consumed;

}




/* returns length of cookie */ 
int gen_b64_cookie_field(char* outbuf, char* data, int datalen) {
  int onecookielen;
  int consumed = 0;
  int cookielen = 0;
  
  


  while (datalen - consumed  > 0) {
   int cnt = gen_one_b64cookie(outbuf, onecookielen, data + consumed, datalen - consumed);

    if (cnt < 0) {
      fprintf(stderr, "error: couldn't create cookie %d\n", cnt);
      return cnt;
    }

    consumed += cnt;
    outbuf += onecookielen;
    cookielen += onecookielen;
    
    if (datalen - consumed < 5) {
      memcpy(outbuf, data+consumed, datalen-consumed);
      return cookielen + datalen - consumed;
    }


    if (datalen - consumed > 0) {
      outbuf[0] = ';';
      outbuf++;
      cookielen++;
    }
  }


  return cookielen;
}



void sanitize_b64(char* input, int len) {
  char* i = strchr(input, '/');
  int eqcnt = 0;

  printf("len = %d\n", len);
  
  while (i != NULL) {
    *i = '_';
    i = strchr(i+1, '/');
  }

  i = strchr(input, '+');

  while (i != NULL) {
    *i = '.';
    i = strchr(i+1, '+');
  }

  if (input[len-2] == '=')
    eqcnt = 2;
  else if (input[len-1] == '=')
    eqcnt = 1;


  while (eqcnt > 0) {
    int pos = rand() % (len - 1) + 1;
    if (pos >= len - eqcnt) {
      input[pos] = '-';
      eqcnt--;
      continue;
    }
    
    //shift characters up and insert '-' in the middle
    for (int j=len-eqcnt; j > pos; j--)
      input[j] = input[j-1];

    input[pos] = '-';
    eqcnt--;

  }
  
}


void desanitize_b64(char* input, int len) {
  char* i = strchr(input, '_');


  printf("len = %d\n", len);
  while (i != NULL) {
    *i = '/';
    i = strchr(i+1, '_');
  }

  i = strchr(input, '.');

  while (i != NULL) {
    *i = '+';
    i = strchr(i+1, '.');
  }

  
  i = strchr(input, '-');
  if (i != NULL) {
    int j;
    for (j=i-input; j < len-1; j++)
      input[j] = input[j+1];
    input[len-1] = '=';


    i = strchr(input, '-');

    if (i != NULL) {
      for (j=i-input; j < len-2; j++)
	input[j] = input[j+1];
      input[len-2] = '=';
    }
    
  }

}





// int main () {
//   char outbuf[200];

//   char data[56] = "ba239023820389023802380389abc2322132321932847203aedfasd";
//   char data2[200];
//   int cookielen;

//   srand(time(NULL));

//   bzero(data2, sizeof(data2));
//   bzero(outbuf, sizeof(outbuf));

//   base64::encoder E;
//   E.encode(data, strlen(data), data2);
//   E.encode_end(data2+strlen(data2));
//   printf("%s", data2);
//   // remove trailing newline
//   data2[strlen(data2) - 1] = 0;

//   // /* substitute / with _, + with ., = with - that maybe inserted anywhere in the middle */

//   sanitize_b64(data2, strlen(data2));
//   printf("%s\n", data2);

//   cookielen = gen_b64_cookie_field((char*) outbuf, (char*) data2, strlen(data2));
//   printf("cookie=%s\n", outbuf);

//   bzero(data2, sizeof(data2));
//   cookielen = unwrap_b64_cookie((char*) outbuf, (char*) data2, strlen(outbuf));


//   desanitize_b64(data2, cookielen);
//   printf("%s\n", data2);
//   printf("%d\n", cookielen);

//   data2[strlen(data2)] = '\n';


//   bzero(outbuf, 200);


  
//   base64::decoder D;
//   D.decode(data2, strlen(data2), outbuf);
//   printf("%s\n", outbuf);



// }




