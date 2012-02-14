#ifndef _B64_COOKIES_H
#define _B64_COOKIES_H



#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include "b64encode.h"
#include "b64decode.h"

int unwrap_b64_cookie( char* inbuf,  char* outbuf, int buflen);
int gen_b64_cookie_field( char* outbuf,  char* data, int datalen);
int gen_one_b64cookie( char* outbuf, int& cookielen,  char* data, int datalen);
void sanitize_b64(char* input, int len);
void desanitize_b64(char* input, int len);


#endif
