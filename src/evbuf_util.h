/**
   Copyright 2013 Tor Inc
   
   tools to work with evbuffers, but not included into util.h to
   prevent mandatory link to libevent for tools which do not need it
   AUTHOR:
   - Vmon: Initial version, 
   
 */

#include <event2/buffer.h>
/**
   Convert the evbuffer into a consecutive memory block

   @param scattered_buffer the data in evbuffer type
   @param memory_block return data in consecutive memory block

   @return the length of the memory block or < 0 in case of error
*/
int evbuffer_to_memory_block(evbuffer* scattered_buffer, uint8_t** memory_block);
int JS_evbuffer_to_memory_block(evbuffer* scattered_buffer, uint8_t** memory_block);
