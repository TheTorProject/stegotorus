#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include "zlib.h"


int def(char *source, int slen, char *dest, int dlen, int level);
int inf(char *source, int slen, char *dest, int dlen);
void zerr(int ret);
int gzInflate(char *source, int slen, char *dest, int dlen);
int gzDeflate(char* start, off_t insz, char *buf, off_t outsz, time_t mtime);
unsigned int generate_crc32c(char *buffer, size_t length);
