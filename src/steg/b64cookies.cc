/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "b64cookies.h"

size_t
unwrap_b64_cookies(char *outbuf, const char *inbuf, size_t inlen)
{
  size_t i, j;

  for (i = 0, j = 0; i < inlen; i++) {
    char c = inbuf[i];
    if (c != ' ' && c != ';' && c != '=')
      outbuf[j++] = c;
  }

  return j;
}

static size_t
gen_one_cookie(char *&outbuf, const char *&inbuf, size_t inlen)
{
  size_t adv_in = 0;
  size_t adv_out = 0;
  size_t namelen, cookielen;

  if (inlen < 5) {
    memcpy(outbuf, inbuf, inlen);
    outbuf += inlen;
    inbuf += inlen;
    return inlen;
  }

  if (inlen < 10) {
    namelen = rand() % 5 + 1;
  } else {
    namelen = rand() % 10 + 1;
  }

  cookielen = rand() % (inlen * 2 / 3);
  if (cookielen > inlen - namelen)
    cookielen = inlen - namelen;

  memcpy(outbuf, inbuf, namelen);
  adv_in += namelen;
  adv_out += namelen;

  outbuf[adv_out++] = '=';

  memcpy(outbuf + adv_out, inbuf + adv_in, cookielen);
  adv_in += cookielen;
  adv_out += cookielen;

  outbuf += adv_out;
  inbuf += adv_in;
  return adv_in;
}

/* returns length of cookie */
size_t
gen_b64_cookies(char *outbuf, const char *inbuf, size_t inlen)
{
  char *outp = outbuf;
  const char *inp = inbuf;
  size_t processed = 0;

  while (processed < inlen) {
    processed += gen_one_cookie(outp, inp, inlen - processed);

    size_t remain = inlen - processed;
    if (remain < 5) {
      memcpy(outp, inp, remain);
      outp += remain;
      inp += remain;
      break;
    }
    if (remain > 0)
      *outp++ = ';';
  }

  return outp - outbuf;
}
