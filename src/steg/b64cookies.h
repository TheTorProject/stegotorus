/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _B64_COOKIES_H
#define _B64_COOKIES_H

size_t unwrap_b64_cookies(char *outbuf, const char *inbuf, size_t inlen);
size_t gen_b64_cookies(char *outbuf, const char *inbuf, size_t inlen);

#endif
