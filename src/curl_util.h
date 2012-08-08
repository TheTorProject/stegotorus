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

#endif
