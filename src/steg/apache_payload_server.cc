#include <curl/curl.h>
#include <iostream>
#include <fstream>

using namespace std;

#include "util.h"

/**
  The constructor reads the payload database prepared by scraper
  and initialize the payload table.
*/
ApachePayloadServer::ApachePayloadServer(MachineSide init_side, string database_filename)
  :PayloadServer(init_side),_database_filename(database_filename)
{

  /* First we read all the payload info from the db file  */
  ifstream payload_info_stream;

  payload_info_stream.open(_database_filename);

  if (!payload_info_stream.is_open())
    {
      fprintf(stderr, "Cannot open payload info file.");
      return;
    }

  while (!payload_info_stream.eof()) {
    PayloadInfo cur_payload_info;
    unsigned int file_id;
    string cur_hash;

    payload_info_stream >> file_id;
    payload_info_stream >>  cur_payload_info.type;
    payload_info_stream >>  cur_hash;
    payload_info_stream >>  cur_payload_info.capacity;
    payload_info_stream >>  cur_payload_info.length;
    payload_info_stream >>  cur_payload_info.url;

    _payload_database.payloads.insert(pair<string, PayloadInfo>(cur_hash, cur_payload_info));

  } // while

  log_debug("loaded %ld payloads from %s\n", _payload_database.payloads.size(), _database_filename.c_str());

  payload_info_stream.close();

  if (!(_curl_obj = curl_easy_init()))
    log_abort("Failed to initiate the curl object");

}
unsigned int ApachePayloadServer::find_client_payload(char* buf, int len, int type)
{
  (void)buf; 
  (void)len; 
  (void)type;
  //TODO to be implemented 
  return 0;
}


int ApachePayloadServer::get_payload ( int contentType, int cap, char** buf, int* size)
{
  int found = 0, numCandidate = 0;

  //log_debug("contentType = %d, initTypePayload = %d, typePayloadCount = %d",
  //            contentType, pl.initTypePayload[contentType],
  //          pl.typePayloadCount[contentType]);

  //get payload is not supposed to act like this but for the sake 
  //of testing and compatibility we are simulating the original 
  //get_payload
  map<string, PayloadInfo>::iterator itr_payloads, itr_first, itr_best;
  for (itr_payloads = _payload_database.payloads.begin(), itr_best = _payload_database.payloads.begin(); itr_payloads != _payload_database.payloads.end() && numCandidate < MAX_CANDIDATE_PAYLOADS; itr_payloads++) {

    if ((*itr_payloads).second.capacity <= (unsigned int)cap || (*itr_payloads).second.type != (unsigned int)contentType)
      continue;

    found = true;
    itr_first = itr_payloads;
    numCandidate++;

    if ((*itr_best).second.length > (*itr_payloads).second.length ||
        (*itr_best).second.type != (unsigned int) contentType)
      itr_best = itr_payloads;

  }

  if (found)
    {
      log_debug("cur payload size=%d, best payload size=%d, num candidate=%d\n",
              (*itr_first).second.length,
              (*itr_best).second.length,
              numCandidate);
      *size = fetch_url_raw((*itr_best).second.url, (*itr_best).second.length, *buf);
    if (*size == 0)
      {
         log_debug("Failed fetch the url %s", (*itr_best).second.url.c_str());
         return 0;
      }
    return 1;
  } else {
    return 0;
  }

}

unsigned long ApachePayloadServer::fetch_url_raw(string url, unsigned long payload_length, char* buf)
{
  CURLcode res;
  pair<unsigned long, char*> res_payload;
  size_t actual_length;
  long sockextr;
 
  if (payload_length > c_max_buffer_size)
    {
      log_debug("Too big of payload");
      return 0;
    }
    
  curl_easy_setopt(_curl_obj, CURLOPT_URL, url.c_str());
 
  /* Perform the request, res will get the return code */ 
  res = curl_easy_perform(_curl_obj);
  /* Check for errors */ 
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
 
  /* Extract the socket from the curl handle - we'll need it for waiting.
   * Note that this API takes a pointer to a 'long' while we use
   * curl_socket_t for sockets otherwise.
   */ 
  res = curl_easy_getinfo(_curl_obj, CURLINFO_LASTSOCKET, &sockextr);
 
  if(CURLE_OK != res)
    {
      printf("Error: %s\n", curl_easy_strerror(res));
      return 0;

    }
 
    curl_socket_t sockfd = sockextr;
 
    wait_on_socket(sockfd, 1, 60000L);
    res = curl_easy_recv(_curl_obj, buf, payload_length, &actual_length);
 
    if(CURLE_OK != res)
      {
        log_debug("Error in receiving data from web server.");
        return 0;
      }
     
    /* always cleanup */ 
    curl_easy_cleanup(curl);

    return (pair<unsigned long, char*>)(actual_length, buf);

}
n
