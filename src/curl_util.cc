/* Copyright 2012 vmon
 * See LICENSE for other credits and copying information
 * 
 * This file contains functions are used to facilitate the
 * usage of curl library
 */
#include <curl/curl.h>

#include "util.h"
#include "connections.h"
#include "curl_util.h"


int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;
 
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec= (timeout_ms % 1000) * 1000;
 
  FD_ZERO(&infd);
  FD_ZERO(&outfd);
  FD_ZERO(&errfd);
 
  FD_SET(sockfd, &errfd); /* always check for error */ 
 
  if(for_recv)
  {
    FD_SET(sockfd, &infd);
  }
  else
  {
    FD_SET(sockfd, &outfd);
  }
 
  /* select() returns the number of signalled sockets or -1 */ 
  res = select(sockfd + 1, &infd, &outfd, &errfd, &tv);
  return res;
}

size_t
discard_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void) ptr;
  log_debug((conn_t*) userdata, "discarder received %lu bytes", size * nmemb);
  return size * nmemb;
}
