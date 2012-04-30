/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _COOKIES_H
#define _COOKIES_H

int unwrap_cookie(unsigned char* inbuf, unsigned char* outbuf, int buflen);
int gen_cookie_field(unsigned char* outbuf, int total_cookie_len,
                     unsigned char* data, int datalen);
int gen_one_cookie(unsigned char* outbuf, int cookielen,
                   unsigned char* data, int datalen);
int gen_one_cookie2(unsigned char* outbuf, int cookielen,
                    unsigned char* data, int datalen);
int gen_cookie_field2(unsigned char* outbuf, int total_cookie_len,
                      unsigned char* data, int datalen);

#endif
