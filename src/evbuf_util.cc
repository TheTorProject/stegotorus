#include <assert.h>
#include "evbuf_util.h"

#include "util.h"
/*********************** Data Manipulation **********************/
/**
   Convert the evbuffer into a consecutive memory block

   @param scattered_buffer the data in evbuffer type
   @param memory_block return data in consecutive memory block

   @return the length of the memory block or < 0 in case of error
*/
int 
evbuffer_to_memory_block(evbuffer* scattered_buffer, uint8_t** memory_block)
{

  size_t sbuflen = evbuffer_get_length(scattered_buffer);

  int nv = evbuffer_peek(scattered_buffer, sbuflen, NULL, NULL, 0);
  evbuffer_iovec* iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);

  if (evbuffer_peek(scattered_buffer, sbuflen, NULL, iv, nv) != nv) {
    free(iv);
    return -1;
  }

  assert(*memory_block = new uint8_t[sbuflen]); 
  //Vmon: Should I use xzalloc? don't
  //think so, new is overloaded to 
  //handle delete: No new calls xzalloc.
  
  size_t cnt = 0;
  for (int i = 0; i < nv; i++) {
    const unsigned char *p = (const unsigned char *)iv[i].iov_base;
    const unsigned char *limit = p + iv[i].iov_len;
    while (p < limit && cnt < sbuflen) {
      (*memory_block)[cnt++] = *p++;
    }
  }

  free(iv);

  return sbuflen;

}

int 
JS_evbuffer_to_memory_block(evbuffer* scattered_buffer, uint8_t** memory_block)
{

  size_t sbuflen = evbuffer_get_length(scattered_buffer);
  size_t data_len = 0;
  int nv = evbuffer_peek(scattered_buffer, sbuflen, NULL, NULL, 0);
  evbuffer_iovec* iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);

  if (evbuffer_peek(scattered_buffer, sbuflen, NULL, iv, nv) != nv) {
    free(iv);
    return -1;
  }

  assert(*memory_block = new uint8_t[sbuflen*2]); 
  //Vmon: Should I use xzalloc? don't
  //think so, new is overloaded to 
  //handle delete: No new calls xzalloc.
  
  size_t cnt = 0;
  for (int i = 0; i < nv; i++) {
    const uint8_t *p = (const unsigned char *)iv[i].iov_base;
    const uint8_t *limit = p + iv[i].iov_len;
    uint8_t c;
    while (p < limit && cnt < sbuflen) {
      //(*memory_block)[cnt++] = *p++; may need to move parentheses around a bit
      c = *p++;
      (*memory_block)[data_len] = "0123456789abcdef"[(c & 0xF0) >> 4]; //does this need to change to 8, I don't think so, just hex encoding, this function is present elsewhere too
      (*memory_block)[data_len+1] = "0123456789abcdef"[(c & 0x0F) >> 0];
      data_len += 2;
      cnt++;
    }
  }

  free(iv);

  return sbuflen;

}

