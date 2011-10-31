#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include "zlib.h"
#include "zpack.h"


#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */


int def(char *source, int slen, char *dest, int dlen, int level)
{
  int ret, flush;
  unsigned have;
  z_stream strm;
  unsigned char in[CHUNK];
  unsigned char out[CHUNK];
  int dlen_orig = dlen;

  /* allocate deflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  ret = deflateInit(&strm, level);
  if (ret != Z_OK)
    return ret;

  /* compress until end of file */
  do {

    if (slen > CHUNK)
      strm.avail_in = CHUNK;
    else
      strm.avail_in = slen;

    memcpy (in, source, strm.avail_in);
    slen = slen - strm.avail_in;
    source - source + strm.avail_in;

    flush = (slen == 0) ? Z_FINISH : Z_NO_FLUSH;
    strm.next_in = in;

    /* run deflate() on input until output buffer not full, finish
       compression if all of source has been read in */
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = deflate(&strm, flush);    /* no bad return value */
      assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      have = CHUNK - strm.avail_out;

      if ((unsigned int) dlen < have) {
	fprintf(stderr, "dest buf too small!\n");
	return Z_ERRNO;
      }

      memcpy(dest, out, have);
      dest += have;
      dlen = dlen - have;
    } while (strm.avail_out == 0);
    assert(strm.avail_in == 0);     /* all input will be used */

    /* done when last data in file processed */
  } while (flush != Z_FINISH);
  assert(ret == Z_STREAM_END);        /* stream will be complete */

  /* clean up and return */
  (void)deflateEnd(&strm);

  printf("hello here...\n");
  return (dlen_orig - dlen);
  //  return Z_OK;
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */




int inf(char *source, int slen, char *dest, int dlen)
{
  int ret;
  unsigned have;
  z_stream strm;
  unsigned char in[CHUNK];
  unsigned char out[CHUNK];
  int dlen_orig = dlen;


  /* allocate inflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  ret = inflateInit(&strm);
  if (ret != Z_OK)
    return ret;

  /* decompress until deflate stream ends or end of file */
  do {

    if (slen == 0)
      break;
	
    if (slen > CHUNK)
      strm.avail_in = CHUNK;
    else
      strm.avail_in = slen;

    memcpy(in, source, strm.avail_in);
    slen = slen - strm.avail_in;
    source = source + strm.avail_in;


      
    strm.next_in = in;

    /* run inflate() on input until output buffer not full */
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = inflate(&strm, Z_NO_FLUSH);
      assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      switch (ret) {
      case Z_NEED_DICT:
	ret = Z_DATA_ERROR;     /* and fall through */
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
	(void)inflateEnd(&strm);
	return ret;
      }
      have = CHUNK - strm.avail_out;


      if ((unsigned int) dlen < have) {
	fprintf(stderr, "dest buf too small!\n");
	return Z_ERRNO;
      }

      memcpy(dest, out, have);
      dest += have;
      dlen = dlen - have;

    } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
  } while (ret != Z_STREAM_END);

  /* clean up and return */
  (void)inflateEnd(&strm);

  if (ret == Z_STREAM_END)
    return dlen_orig - dlen;
  return Z_DATA_ERROR;
}

/* report a zlib or i/o error */
void zerr(int ret)

{
  fputs("zpipe: ", stderr);
  switch (ret) {
  case Z_ERRNO:
    if (ferror(stdin))
      fputs("error reading stdin\n", stderr);
    if (ferror(stdout))
      fputs("error writing stdout\n", stderr);
    break;
  case Z_STREAM_ERROR:
    fputs("invalid compression level\n", stderr);
    break;
  case Z_DATA_ERROR:
    fputs("invalid or incomplete deflate data\n", stderr);
    break;
  case Z_MEM_ERROR:
    fputs("out of memory\n", stderr);
    break;
  case Z_VERSION_ERROR:
    fputs("zlib version mismatch!\n", stderr);
  }
}








/* assumes that we know there is exactly 10 bytes of gzip header */

int gzInflate(char *source, int slen, char *dest, int dlen)
{
  int ret;
  unsigned have;
  z_stream strm;
  unsigned char in[CHUNK];
  unsigned char out[CHUNK];
  int dlen_orig = dlen;


  /* allocate inflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;


  ret = inflateInit2(&strm, -MAX_WBITS);
  if (ret != Z_OK)
    return ret;

  source = source + 10;
  slen -= 10;

  /* decompress until deflate stream ends or end of file */
  do {

    if (slen == 0)
      break;
	
    if (slen > CHUNK)
      strm.avail_in = CHUNK;
    else
      strm.avail_in = slen;

    memcpy(in, source, strm.avail_in);
    slen = slen - strm.avail_in;
    source = source + strm.avail_in;


      
    strm.next_in = in;

    /* run inflate() on input until output buffer not full */
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = inflate(&strm, Z_NO_FLUSH);
      assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
      switch (ret) {
      case Z_NEED_DICT:
	ret = Z_DATA_ERROR;     /* and fall through */
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
	(void)inflateEnd(&strm);
	return ret;
      }
      have = CHUNK - strm.avail_out;

      if ((unsigned int) dlen < have) {
	fprintf(stderr, "dest buf too small!\n");
	return Z_ERRNO;
      }

      memcpy(dest, out, have);
      dest += have;
      dlen = dlen - have;

    } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
  } while (ret != Z_STREAM_END);

  /* clean up and return */
  (void)inflateEnd(&strm);

  if (ret == Z_STREAM_END)
    return dlen_orig - dlen;
  return Z_DATA_ERROR;
}







int gzDeflate(char* start, off_t insz, char *buf, off_t outsz, time_t mtime) {
  unsigned char *c;
  unsigned long crc;
  z_stream z;

  z.zalloc = Z_NULL;
  z.zfree = Z_NULL;
  z.opaque = Z_NULL;

  if (Z_OK != deflateInit2(&z,
			   Z_DEFAULT_COMPRESSION,
			   Z_DEFLATED,
			   -MAX_WBITS,  /* supress zlib-header */
			   8,
			   Z_DEFAULT_STRATEGY)) {
    return -1;
  }

  z.next_in = (unsigned char *)start;
  z.avail_in = insz;
  z.total_in = 0;


  /* write gzip header */

  c = (unsigned char *) buf;
  c[0] = 0x1f;
  c[1] = 0x8b;
  c[2] = Z_DEFLATED;
  c[3] = 0; /* options */
  c[4] = (mtime >>  0) & 0xff;
  c[5] = (mtime >>  8) & 0xff;
  c[6] = (mtime >> 16) & 0xff;
  c[7] = (mtime >> 24) & 0xff;
  c[8] = 0x00; /* extra flags */
  c[9] = 0x03; /* UNIX */

  z.next_out = c + 10;
  z.avail_out = outsz - 10 - 8;
  z.total_out = 0;

  if (Z_STREAM_END != deflate(&z, Z_FINISH)) {
    deflateEnd(&z);
    return -1;
  }


  crc = generate_crc32c(start, insz);

  c = (unsigned char *)buf + 10 + z.total_out; 

  c[0] = (crc >>  0) & 0xff;
  c[1] = (crc >>  8) & 0xff;
  c[2] = (crc >> 16) & 0xff;
  c[3] = (crc >> 24) & 0xff;
  c[4] = (z.total_in >>  0) & 0xff;
  c[5] = (z.total_in >>  8) & 0xff;
  c[6] = (z.total_in >> 16) & 0xff;
  c[7] = (z.total_in >> 24) & 0xff;



  if (Z_OK != deflateEnd(&z)) {
    return -1;
  }

  return 10 + z.total_out + 8;

}





/* compress or decompress from stdin to stdout */
/* int main(int argc, char **argv) */
/* { */
/*   int ret; */
/*   char buf1[32] = "abcasdfadfadfadf23fasdfa23sdfsdf"; */
/*   char buf2[100]; */
/*   char buf3[100]; */
/*   int i; */

/*   bzero(buf2, sizeof(buf2)); */
/*   bzero(buf3, sizeof(buf3)); */
  

/*   //  ret = def(buf1, 3, buf2, 100,  Z_DEFAULT_COMPRESSION); */
/*   ret = gzDeflate(buf1, sizeof(buf1), buf2, sizeof(buf2), time(NULL)); */
/*   if (ret <= 0) */
/*     zerr(ret); */

/*   /\*  for (i=0; i < ret; i++) */
/*     putc(buf2[i], stdout); */
/*   *\/ */


/*   //  printf("len = %d\n", ret); */

/*   ret = gzInflate(buf2, ret, buf3, 100); */
/*   if (ret <= 0) */
/*     zerr(ret); */
/*   printf("hello %s\n", buf3); */


/* } */
