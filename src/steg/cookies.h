#ifndef _COOKIES_H
#define _COOKIES_H



#include <stdio.h>
#include <strings.h>
#include <stdlib.h>

int unwrap_cookie(unsigned char* inbuf, unsigned char* outbuf, int buflen);
int gen_cookie_field(unsigned char* outbuf, int total_cookie_len, unsigned char* data, int datalen);
int gen_one_cookie(unsigned char* outbuf, int cookielen, unsigned char* data, int datalen);
int gen_one_cookie2(unsigned char* outbuf, int cookielen, unsigned char* data, int datalen);
int gen_cookie_field2(unsigned char* outbuf, int total_cookie_len, unsigned char* data, int datalen);


#endif
