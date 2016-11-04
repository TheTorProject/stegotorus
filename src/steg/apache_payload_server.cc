#include <fstream>
#include <sstream>
#include <vector>
#include <boost/filesystem.hpp>
#include <assert.h>

using namespace std;
using namespace boost::filesystem;

#include "util.h"
#include "curl_util.h"
#include "crypt.h"
#include "rng.h"
#include "apache_payload_server.h"

#include "http_steg_mods/file_steg.h"
#include "http_steg_mods/jpgSteg.h"
#include "payload_scraper.h"

/**
  The constructor reads the payload database prepared by scraper
  and initialize the payload table.
*/

typedef string (*RetrievingFunc)(const string&);

ApachePayloadServer::ApachePayloadServer(MachineSide init_side, const string& database_filename, const string& cover_server, const string& cover_list)
  :PayloadServer(init_side),_database_filename(database_filename),
   _apache_host_name((cover_server.empty()) ? "127.0.0.1" : cover_server),
   c_max_buffer_size(HTTP_MSG_BUF_SIZE),
   _payload_cache(this, &ApachePayloadServer::fetch_hashed_url, 
   c_PAYLOAD_CACHE_ELEMENT_CAPACITY),   
   chosen_payload_choice_strategy(/*c_random_payload_choice*/c_most_efficient_payload_choice)
{
  /* Ideally this should check the side and on client side
     it should not attempt openning the the database file but
     for now we keep it for testing */
  
  //(_side == server_side) {
  /* First we read all the payload info from the db file  */
  std::ifstream payload_info_stream;

  if (_side == server_side) {
    //Initializing type specific data, we initiate with max_capacity = 0, count = 0
    //I don't think we need this as we have the default constructor doing the same
    TypeDetail init_empty_type;
    for(unsigned int cur_type = 1; cur_type < c_no_of_steg_protocol+1; cur_type++)
      _payload_database.type_detail[cur_type] = init_empty_type;
    //it should be like this but beacause they are not pointers 
    //we are in trouble need to change the type to pointer
    //_payload_database.type_detail = new TypeDetail[c_no_of_steg_protocol];

    if (!boost::filesystem::exists(_database_filename)) {
        log_debug("payload database does not exists.");
        log_debug("scarping payloads to create the database...");

        PayloadScraper my_scraper(_database_filename, _apache_host_name,  cover_list);
        my_scraper.scrape();

      }
    
    payload_info_stream.open(_database_filename, std::ifstream::in);
    if (!payload_info_stream.is_open()) {
      log_abort("Cannot open payload info file.");
    }
      
    unsigned long file_id;
    while (payload_info_stream >> file_id) {
      PayloadInfo cur_payload_info;

      if (_payload_database.payloads.find(cur_payload_info.url_hash) != _payload_database.payloads.end()) {
        log_warn("duplicate url in the url list: %s", cur_payload_info.url.c_str());
        continue;
      }

      payload_info_stream >>  cur_payload_info.type;
      payload_info_stream >>  cur_payload_info.url_hash;
      payload_info_stream >>  cur_payload_info.capacity;
      payload_info_stream >>  cur_payload_info.length;
      payload_info_stream >>  cur_payload_info.url;
      payload_info_stream >>  cur_payload_info.absolute_url_is_absolute;
      payload_info_stream >>  cur_payload_info.absolute_url;

        
      _payload_database.payloads.insert(pair<string, PayloadInfo>(cur_payload_info.url_hash, cur_payload_info));
      _payload_database.sorted_payloads.push_back(EfficiencyIndicator(cur_payload_info.url_hash, cur_payload_info.length));
                                                  
      //update type related global data 
      _payload_database.type_detail[cur_payload_info.type].count++;
      if (cur_payload_info.capacity > _payload_database.type_detail[cur_payload_info.type].max_capacity)
        _payload_database.type_detail[cur_payload_info.type].max_capacity = cur_payload_info.capacity;

    } // while
     
    if (payload_info_stream.bad())
      log_abort("payload info file corrupted.");
        
    _payload_database.sorted_payloads.sort();
    
    log_debug("loaded %ld payloads from %s\n", _payload_database.payloads.size(), _database_filename.c_str());
    
    //This is how server side initiates the uri dict
    init_uri_dict();
  }
  else{ //client side
    payload_info_stream.open(_database_filename, std::ifstream::in);
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
  curl_easy_setopt(_curl_obj, CURLOPT_WRITEFUNCTION, curl_read_data_cb);

}

unsigned int
ApachePayloadServer::find_client_payload(char* buf, int len, int type)
{
  (void)buf; 
  (void)len;
  (void)type;

  //TODO to be implemented 
  return 0;
}

int
ApachePayloadServer::get_payload( int contentType, int cap, char** buf, int* size, double noise2signal, std::string* payload_id_hash)
{
  int found = 0, numCandidate = 0;

  //log_debug("contentType = %d, initTypePayload = %d, typePayloadCount = %d",
  //            contentType, pl.initTypePayload[contentType],
  //          pl.typePayloadCount[contentType]);

  //get payload is not supposed to act like this but for the sake 
  //of testing and compatibility we are simulating the original 
  //get_payload
  assert(cap != 0); //why do you ask for zero capacity?
  PayloadInfo* itr_first, *cur_payload_candidate, *itr_best = NULL;
  if (chosen_payload_choice_strategy == c_most_efficient_payload_choice) {
    list<EfficiencyIndicator>::iterator  itr_payloads = _payload_database.sorted_payloads.begin();
    
    cur_payload_candidate = &_payload_database.payloads[itr_payloads->url_hash];
    while(itr_payloads != _payload_database.sorted_payloads.end() && 
          (cur_payload_candidate->corrupted ||
           cur_payload_candidate->capacity < (unsigned int)cap || 
           cur_payload_candidate->type != (unsigned int)contentType || 
           cur_payload_candidate->length/(double)cap < noise2signal)) {
    itr_payloads++; numCandidate++;
    cur_payload_candidate = &_payload_database.payloads[itr_payloads->url_hash];
    
    }

    if (itr_payloads != _payload_database.sorted_payloads.end() && cur_payload_candidate->length < c_max_buffer_size)
      {
        found = true;
        itr_first = itr_best = cur_payload_candidate;
      }
  }
  else { //    c_random_payload_choice
    PayloadDict::iterator itr_payloads;
      while(numCandidate < MAX_CANDIDATE_PAYLOADS) {
        itr_payloads = _payload_database.payloads.begin();
        advance(itr_payloads, rng_int(_payload_database.payloads.size()));  
        if ((*itr_payloads).second.corrupted ||
            (*itr_payloads).second.capacity <= (unsigned int)cap || 
            (*itr_payloads).second.type != (unsigned int)contentType || 
            (*itr_payloads).second.length > c_max_buffer_size || 
            (*itr_payloads).second.length/(double)cap < noise2signal)
            continue;

        found = true;
        itr_first = &((*itr_payloads).second);
        numCandidate++;

        if (itr_best == NULL)
          itr_best = itr_first;
        else if (itr_best->length > itr_first->length)
          itr_best = itr_first;

      }
  }

  if (found)
    {
      log_debug("cur payload size=%d, best payload size=%d, num candidate=%d for transmiting %d bytes\n",
                itr_first->length,
                itr_best->length,
                numCandidate,
                cap);

      string& best_payload = _payload_cache((itr_best->absolute_url_is_absolute ? "" : "http://" + _apache_host_name + "/") + (itr_best->absolute_url)); //this is a permanent object in cache so it is ok to get a reference to it.
      //if curl fails the size will be zero.
      *buf = (char*)best_payload.c_str();
      *size = best_payload.length();
      if (payload_id_hash)
        *payload_id_hash = itr_best->url_hash;

      return 1;
      
    } 
  
  /*not found*/
  return 0;
}


/**
   This function is supposed to be given to the cache class to be used to retrieve the
   the element when it isn't in the hash table

   @param url_hash the sha-1 hash of the url
 */
string
ApachePayloadServer::fetch_hashed_url(const string& url)
{
  stringstream tmp_stream_buf;
  string payload_uri = url;

  log_debug("asking cover server for payload %s", payload_uri.c_str());
  size_t payload_size = fetch_url_raw(_curl_obj, payload_uri, tmp_stream_buf);
  if (payload_size == 0) {
    log_warn("Failed fetch the url %s", payload_uri.c_str()); //here we should signal that we failed
    //to retreieve the file and mark it as unacceptable
    return string();
  }

  return tmp_stream_buf.str();

}

bool
ApachePayloadServer::init_uri_dict()
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

bool
ApachePayloadServer::init_uri_dict(istream& dict_stream)
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

  log_debug("corrupted dictionary buffer");
  return false;
  
}

void
ApachePayloadServer::export_dict(iostream& dict_stream)
{
  URIDict::iterator itr_uri;
  for(itr_uri = uri_dict.begin(); itr_uri != uri_dict.end(); itr_uri++)
    {
      dict_stream << itr_uri->URL.c_str() << endl;
    }

  log_debug("uri dictionary of size %ld has been exported.", uri_dict.size());
  
}

const uint8_t*
ApachePayloadServer::compute_uri_dict_mac()
{
  stringstream dict_str_stream;
  export_dict(dict_str_stream);
  
  sha256((const uint8_t*)dict_str_stream.str().c_str(), dict_str_stream.str().size(), _uri_dict_mac);

  return _uri_dict_mac;

}

bool
ApachePayloadServer::store_dict(char* dict_buf, size_t dict_buf_size)
{

  std::ofstream dict_file(_database_filename);

  if (!dict_file.is_open()){
    log_warn("error in openning file:%s to store the uri dict: %s", _database_filename.c_str(), strerror(errno));
    return false;
  }

  dict_file.write(dict_buf, dict_buf_size);
  if (dict_file.bad()){
    log_warn("error in storing the uri dict: %s",strerror(errno));
    dict_file.close();
    return false;
  }

  dict_file.close();
  return true;
}

ApachePayloadServer::~ApachePayloadServer()
{
  /* always cleanup */ 
  log_debug("cleaning up curl easy handle for payload retrieval");
  curl_easy_cleanup(_curl_obj);

}

int 
ApachePayloadServer::find_url_type(const char* uri)
{

  string file_url(uri);
  string ext, filename;

  log_debug("uri %s", file_url.c_str());
  size_t last_slash = file_url.rfind("/");
  if (last_slash == string::npos) //AFAIK url needs one slash
    filename = file_url;
  else
    filename = (last_slash == file_url.length() - 1) ? "" : file_url.substr(last_slash+1);
  log_debug("filename %s", filename.c_str());
  size_t last_dot = filename.rfind(".");
  if (last_dot == string::npos) 
    ext = "html"; //no filename assume html
  else
    ext = filename.substr(last_dot+1);

  log_debug("ext %s", ext.c_str());
  return extension_to_content_type(ext.c_str());
  
}
