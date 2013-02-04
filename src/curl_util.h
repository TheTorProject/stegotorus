/* Copyright 2012 vmon
 * See LICENSE for other credits and copying information
 * 
 * This file contains the headers for functions are used
 * to facilitate the usage of curl library
 */
#ifndef CURL_UTIL_H
#define CURL_UTIL_H
#include <curl/curl.h>

int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms);

size_t discard_data(char *ptr, size_t size, size_t nmemb, void *userdata);
unsigned long fetch_url_raw(CURL* curl_obj, string& url,  stringstream& buf);


/**
   The call back function that is called when curl request a file from
   the webserver (libcurl calls it write_data for some reason). It has to be static to be able to send it as cb

*/
size_t curl_read_data_cb(void *buffer, size_t size, size_t nmemb, void *userp);

 int sockopt_callback(void *clientp, curl_socket_t curlfd,
                                curlsocktype purpose);

int ignore_close(void *clientp, curl_socket_t curlfd);
int curl_close_socket_cb(void *clientp, curl_socket_t curlfd);

#endif
