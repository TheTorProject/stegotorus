#ifndef STRNCASETSTR_H
#define STRNCASETSTR_H

#include <stddef.h>
#include "stegerrors.h"

#define CASECMPCONST(X,Y) strncasecmp(X,Y,sizeof(Y)-1)
#define STRNCMPCONST(X,Y) strncmp(X,Y,sizeof(Y)-1)

#ifdef __cplusplus
extern "C" {
#endif
  

rcode_t memncpy(void* dst, size_t buf_len, const void* src, size_t len);


/*
 * memcpy with bounds checking.  return -1 on error, 0 if successful
 */
int safe_copy(void* dst, size_t buf_len, const void* src, size_t len);


/*
 * Find the first occurrence of needle in haystack, where the search is limited to the
 * first len characters of haystack.
 */
char *strnstr(const char *s, const char *find, size_t slen);

/*
 * Find the first ***case insensitive*** occurrence of needle in haystack, where the search is limited to the
 * first len characters of haystack.
 */
char *strncasestr(const char *s, const char *find, size_t slen);



#ifdef __cplusplus
}	/*  extern "C" */
#endif /* __cplusplus */


#endif /*  STRNCASETSTR_H */
