#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

#include "util.h"
#include "curl_util.h"
#include "crypt.h"
#include "rng.h"
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
  
  //(_side == server_side) {
  /* First we read all the payload info from the db file  */
  ifstream payload_info_stream;
    
  payload_info_stream.open(_database_filename, ifstream::in);

  if (_side == server_side) {
    //Initializing type specific data, we initiate with max_capacity = 0, count = 0
    _payload_database.type_detail[HTTP_CONTENT_JAVASCRIPT] =  TypeDetail(0, 0);
    _payload_database.type_detail[HTTP_CONTENT_HTML] =  TypeDetail(0, 0);

    _payload_database.type_detail[HTTP_CONTENT_PDF] =  TypeDetail(0, 0);

    _payload_database.type_detail[HTTP_CONTENT_SWF] = TypeDetail(0, 0);

    if (!payload_info_stream.is_open())
        {
          log_abort("Cannot open payload info file.");
        }
      
    unsigned long file_id;
    while (payload_info_stream >> file_id) {
    
      PayloadInfo cur_payload_info;
      string cur_hash;

      payload_info_stream >>  cur_payload_info.type;
      payload_info_stream >>  cur_hash;
      payload_info_stream >>  cur_payload_info.capacity;
      payload_info_stream >>  cur_payload_info.length;
      payload_info_stream >>  cur_payload_info.url;

      _payload_database.payloads.insert(pair<string, PayloadInfo>(cur_hash, cur_payload_info));

      //update type related global data 
      _payload_database.type_detail[cur_payload_info.type].count++;
      if (cur_payload_info.capacity > _payload_database.type_detail[cur_payload_info.type].max_capacity)
        _payload_database.type_detail[cur_payload_info.type].max_capacity = cur_payload_info.capacity;

    } // while
     
    if (payload_info_stream.bad())
      log_abort("payload info file corrupted.");
        
    log_debug("loaded %ld payloads from %s\n", _payload_database.payloads.size(), _database_filename.c_str());
    
    //This is how server side initiates the uri dict
    init_uri_dict();
  }
  else{ //client side
      
    if (!(payload_info_stream.is_open())) //on client side it is not a fatal error
      log_debug("payload info file doesn't exists. I need to request it from server ");
    else {
      if (!init_uri_dict(payload_info_stream))
        log_debug("payload info file is corrupted. I need to request it from server ");
      payload_info_stream.close();
    }

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
  PayloadDict::iterator itr_payloads, itr_first, itr_best = _payload_database.payloads.end();
  while(numCandidate < MAX_CANDIDATE_PAYLOADS) {
    itr_payloads = _payload_database.payloads.begin();
    advance(itr_payloads, rng_int(_payload_database.payloads.size()));
    if ((*itr_payloads).second.capacity <= (unsigned int)cap || (*itr_payloads).second.type != (unsigned int)contentType)
      continue;

    found = true;
    itr_first = itr_payloads;
    numCandidate++;

    if (itr_best == _payload_database.payloads.end())
      itr_best = itr_payloads;
    else if ((*itr_best).second.length > (*itr_payloads).second.length)
      itr_best = itr_payloads;

  }

  if (found)
    {
      log_debug("cur payload size=%d, best payload size=%d, num candidate=%d\n",
                (*itr_first).second.length,
                (*itr_best).second.length,
                numCandidate);
      stringstream tmp_stream_buf;
      string payload_uri = "http://" + _apache_host_name + "/" + (*itr_best).second.url;
      *size = fetch_url_raw(payload_uri, (*itr_best).second.length, tmp_stream_buf);
    if (*size == 0)
      {
         log_abort("Failed fetch the url %s", (*itr_best).second.url.c_str());
         return 0;
      }

    *buf = new char[*size];
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

  log_debug("read total bytes of : %lu:", buf.str().size());
  return buf.tellp();

}

size_t ApachePayloadServer::read_data_cb(void *buffer, size_t size, size_t nmemb, void *userp)
{
  //accumulate everything in a streamstring buffer
  size_t no_bytes_2_read = size * nmemb;
  log_debug("curl received %lu bytes", no_bytes_2_read);
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

  uri_dict.clear();
  uri_decode_book.clear();

  PayloadDict::iterator itr_payloads;
  unsigned long i = 0;

  for (itr_payloads = _payload_database.payloads.begin(); itr_payloads != _payload_database.payloads.end(); itr_payloads++, i++) {

    uri_dict.push_back(URIEntry((*itr_payloads).second.url));
    uri_decode_book[itr_payloads->second.url] = i;
  }

  compute_uri_dict_mac();
  return true;

}

bool ApachePayloadServer::init_uri_dict(istream& dict_stream)
{
  uri_dict.clear();
  uri_decode_book.clear();

  string cur_url;
  for (size_t i = 0; dict_stream >> cur_url; i++) {
    uri_dict.push_back(URIEntry(cur_url));
    uri_decode_book[cur_url] = i;

  }

  log_debug("Stored uri dictionary loaded with %lu entries", uri_dict.size());

  compute_uri_dict_mac();
  if (!dict_stream.bad()) 
    return true;

  log_debug("crrupted dictionary buffer");
  return false;
  
}

void ApachePayloadServer::export_dict(iostream& dict_stream)
{
  URIDict::iterator itr_uri;
  for(itr_uri = uri_dict.begin(); itr_uri != uri_dict.end(); itr_uri++)
    {
      dict_stream << itr_uri->URL.c_str() << endl;
    }
  
}

const unsigned char* ApachePayloadServer::compute_uri_dict_mac()
{
  stringstream dict_str_stream;
  export_dict(dict_str_stream);
  
  sha256((const unsigned char*)dict_str_stream.str().c_str(), dict_str_stream.str().size(), _uri_dict_mac);

  return _uri_dict_mac;

}

bool ApachePayloadServer::store_dict(char* dict_buf, size_t dict_buf_size)
{

  ofstream dict_file(_database_filename);

  if (!dict_file.is_open()){
    log_debug("Fail i nopenning file:%s to store the uri dict", _database_filename.c_str());
    return false;
  }

  dict_file.write(dict_buf, dict_buf_size);
  if (dict_file.bad()){
    log_debug("Error in storing the uri dict");
    dict_file.close();
    return false;
  }

  dict_file.close();
  return true;
}

ApachePayloadServer::~ApachePayloadServer()
{
    /* always cleanup */ 
    curl_easy_cleanup(_curl_obj);

}

int 
ApachePayloadServer::find_url_type(const char* uri) {

  const char* ext = strrchr(uri, '.');

  if (ext == NULL || !strncmp(ext, ".html", 5) || !strncmp(ext, ".htm", 4) || !strncmp(ext, ".php", 4)
      || !strncmp(ext, ".jsp", 4) || !strncmp(ext, ".asp", 4))
    return HTTP_CONTENT_HTML;

  if (!strncmp(ext, ".js", 3) || !strncmp(ext, ".JS", 3))
    return HTTP_CONTENT_JAVASCRIPT;

  if (!strncmp(ext, ".pdf", 4) || !strncmp(ext, ".PDF", 4))
    return HTTP_CONTENT_PDF;


  if (!strncmp(ext, ".swf", 4) || !strncmp(ext, ".SWF", 4))
    return HTTP_CONTENT_SWF;

  return 0;
}
