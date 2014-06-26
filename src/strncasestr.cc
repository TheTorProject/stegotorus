#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


#include "strncasestr.h"

/*
 * Find the first occurrence of needle in haystack, where the search is limited to the
 * first len characters of haystack.
 */
char *strnstr(const char *haystack, const char *needle, size_t len){
  size_t needle_length = strlen(needle);
  int prick = toupper(*needle);
  char c, *front = (char *)haystack;
  //Note: strnstr("0123456789FYY", "FYY", 11) should fail.
  while (((c = *front) != '\0') && (len-- >= needle_length)){
    if (toupper(c) == prick){
      if (strncmp(front, needle, needle_length) == 0){
        return front;
      }
    }
    front++;
  }
  return NULL;
}

/*
 * Find the first ***case insensitive*** occurrence of needle in haystack, where the search is limited to the
 * first len characters of haystack.
 */
char *strncasestr(const char *haystack, const char *needle, size_t len){
  size_t needle_length = strlen(needle);
  int prick = toupper(*needle);
  char c, *front = (char *)haystack;
  //Note: strncasestr("0123456789FYY", "FYY", 11) should fail.
  while (((c = *front) != '\0') && (len-- >= needle_length)){
    if (toupper(c) == prick){
      if (strncasecmp(front, needle, needle_length) == 0){
        return front;
      }
    }
    front++;
  }
  return NULL;
}


/*
 * memcpy with bounds checking
 */
int safe_copy(void* buf, size_t buf_len, const void* src, size_t src_len) {

  if (buf_len < src_len){
    return -1;
  }
  memcpy(buf, src, src_len);
  return 0;

}


rcode_t memncpy(void* buf, size_t buf_len, const void* src, size_t src_len) {

  if (buf_len < src_len){
    return RCODE_ERROR;
  }
  memcpy(buf, src, src_len);
  return RCODE_OK;
}
