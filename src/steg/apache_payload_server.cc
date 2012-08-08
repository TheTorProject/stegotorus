#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

#include "util.h"
#include "curl_util.h"
#include "apache_payload_server.h"

/**
  The constructor reads the payload database prepared by scraper
  and initialize the payload table.
*/
ApachePayloadServer::ApachePayloadServer(MachineSide init_side, string database_filename)
  :PayloadServer(init_side),_database_filename(database_filename)
{
  /* Ideally this should check the side and on client side
     it should not attempt openning the the database file but
     for now we keep it for testing */
  
  if (database_filename != "") { //(_side == server_side) {
    /* First we read all the payload info from the db file  */
    ifstream payload_info_stream;
    
    payload_info_stream.open(_database_filename, ifstream::in);

    if (!payload_info_stream.is_open())
      {
        log_abort("Cannot open payload info file.");
      }

    while (!(payload_info_stream.eof() || payload_info_stream.bad())) {
    
      PayloadInfo cur_payload_info;
      unsigned long file_id;
      string cur_hash;

      payload_info_stream >> file_id;
      payload_info_stream >>  cur_payload_info.type;
      payload_info_stream >>  cur_hash;
      payload_info_stream >>  cur_payload_info.capacity;
      payload_info_stream >>  cur_payload_info.length;
      payload_info_stream >>  cur_payload_info.url;

      _payload_database.payloads.insert(pair<string, PayloadInfo>(cur_hash, cur_payload_info));

    } // while

    if (payload_info_stream.bad())
        log_abort("payload info file corrupted.");
        
    log_debug("loaded %ld payloads from %s\n", _payload_database.payloads.size(), _database_filename.c_str());

    payload_info_stream.close();
  }

  //init curl
  if (!(_curl_obj = curl_easy_init()))
    log_abort("Failed to initiate the curl object");

  curl_easy_setopt(_curl_obj, CURLOPT_HEADER, 1L);
  curl_easy_setopt(_curl_obj, CURLOPT_HTTP_CONTENT_DECODING, 0L);
  curl_easy_setopt(_curl_obj, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
  curl_easy_setopt(_curl_obj, CURLOPT_WRITEFUNCTION, read_data_cb);

}

unsigned int ApachePayloadServer::find_client_payload(char* buf, int len, int type)
{
  (void)buf; 
  (void)len;
  (void)type;

  //TODO to be implemented 
  return 0;
}


int ApachePayloadServer::get_payload( int contentType, int cap, char** buf, int* size)
{
  int found = 0, numCandidate = 0;

  //log_debug("contentType = %d, initTypePayload = %d, typePayloadCount = %d",
  //            contentType, pl.initTypePayload[contentType],
  //          pl.typePayloadCount[contentType]);

  //get payload is not supposed to act like this but for the sake 
  //of testing and compatibility we are simulating the original 
  //get_payload
  PayloadDict::iterator itr_payloads, itr_first, itr_best;
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
      stringstream tmp_stream_buf;
      *size = fetch_url_raw((*itr_best).second.url, (*itr_best).second.length, tmp_stream_buf);
    if (*size == 0)
      {
         log_debug("Failed fetch the url %s", (*itr_best).second.url.c_str());
         return 0;
      }

    tmp_stream_buf.read(*buf, *size);
    return 1;
  } else {
    return 0;
  }

}

unsigned long ApachePayloadServer::fetch_url_raw(string url, unsigned long payload_length, stringstream& buf)
{
  CURLcode res;
  pair<unsigned long, char*> res_payload;
 
  if (payload_length > c_max_buffer_size)
    {
      log_debug("Too big of a payload");
      return 0;
    }

  curl_easy_setopt(_curl_obj, CURLOPT_URL, url.c_str());
  curl_easy_setopt(_curl_obj, CURLOPT_WRITEDATA, (void*)&buf);

  /* Perform the request, res will get the return code */ 
  res = curl_easy_perform(_curl_obj);
  /* Check for errors */ 
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
 
  return buf.tellp();

}

size_t ApachePayloadServer::read_data_cb(void *buffer, size_t size, size_t nmemb, void *userp)
{
  //accumulate everything in a streamstring buffer
  size_t no_bytes_2_read = size * nmemb;
  ((stringstream*)userp)->write((char*) buffer, size * no_bytes_2_read);
  if( ((stringstream*)userp)->bad()){
    log_debug("Error reading data from curl");
    return 0;
  }

  return no_bytes_2_read;

}

bool ApachePayloadServer::init_uri_dict()
{
  if (_payload_database.payloads.size() == 0)
    {
      log_debug("Payload database is empty or not initialized.");
      return false;
    }

  PayloadDict::iterator itr_payloads;

  unsigned long i = 0;

  for (itr_payloads = _payload_database.payloads.begin(); itr_payloads != _payload_database.payloads.end(); itr_payloads++, i++) {

    uri_dict.push_back(URIEntry((*itr_payloads).second.url));
    uri_decode_book[itr_payloads->second.url] = i;
  }

  return true;

}

ApachePayloadServer::~ApachePayloadServer()
{
    /* always cleanup */ 
    curl_easy_cleanup(_curl_obj);

}

