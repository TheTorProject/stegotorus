/* Copyright 2012 vmon
 * See LICENSE for other credits and copying information
 * 
 * This file contains functions are used to facilitate the
 * usage of curl library
 */
#include <curl/curl.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <string>
#include <sstream>

using namespace std;

#include "util.h"
#include "connections.h"
#include "curl_util.h"

extern void downstream_read_cb(struct bufferevent *bev, void *arg);


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

  log_debug((conn_t*) userdata, "discarder received %zu bytes", size * nmemb);
  conn_t *down = (conn_t *)userdata;

  down->ever_received = 1;
  log_debug(down, "%lu bytes available but are going to be discarded",
            (unsigned long)size*nmemb);

  return size * nmemb;
}

/** 
    Uses curl to fetch the raw POST body from Apache to be used as payload.
    return the actual length of the payload or zero in the case of error.

    @param url the url of the requested file
    @param payload_length the length of the requested file this is equal to
    the size of allocated memory for the buf
    @param buf the alocated memory to store the POST reply

    @return 0 if it fails to retrieve the url
*/
unsigned long fetch_url_raw(CURL* curl_obj, string& url,  stringstream& buf)
{
  CURLcode res;

  log_assert(curl_obj);

  curl_easy_setopt(curl_obj, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl_obj, CURLOPT_WRITEDATA, (void*)&buf);

  /* Perform the request, res will get the return code */ 
  res = curl_easy_perform(curl_obj); //need to be turn to non-blocking
  /* Check for errors */ 
  if(res != CURLE_OK) {
    log_debug("curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
    return 0;
  }

  log_debug("read total bytes of : %zu:", buf.str().size());
  log_assert(buf.str()[0]=='H');
  return buf.tellp();

}

size_t curl_read_data_cb(void *buffer, size_t size, size_t nmemb, void *userp)
{
  //accumulate everything in a streamstring buffer
  size_t no_bytes_2_read = size * nmemb;
  log_debug("curl received %zu bytes", no_bytes_2_read);
  ((stringstream*)userp)->write((char*) buffer, size * no_bytes_2_read);
  if( ((stringstream*)userp)->bad()){
    log_debug("Error reading data from curl");
    return 0;
  }

  return no_bytes_2_read;

}

int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  /* This return code was added in libcurl 7.21.5 */ 
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

int ignore_close(void *clientp, curl_socket_t curlfd)
{
  (void) clientp;
  (void) curlfd;
  return 0;
}

int curl_close_socket_cb(void *clientp, curl_socket_t curlfd)
{
  //event* socket_event_handle = (event*) clientp;

  (void) clientp;
  (void) curlfd;
  //if the event is not NULL then we should shutdown the event 
  //first
  /* if (socket_event_handle)
      event_del(socket_event_handle);

      shutdown(curlfd, SHUT_RD | SHUT_WR);*/
  log_debug("preventing curl from closing the socket");

  return 0;
}
