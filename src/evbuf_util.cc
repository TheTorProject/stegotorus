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
