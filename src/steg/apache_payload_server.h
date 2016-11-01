#ifndef _APACHE_PAYLOAD_SERVER_H
#define _APACHE_PAYLOAD_SERVER_H

#include <openssl/sha.h> 
#include <unordered_map>

#include "payload_lru_cache.h"
#include "payload_server.h"


class PayloadScraper; /* Just tell ApachePayloadServer that such a
                        class exists */

class URIEntry
{
  public:
    bool accept_param; /*This is to discriminate between types like html
                                vs cgi, js, etc, but for now I'm not using it
                              */
    string URL;

    URIEntry(string init_URL)
      : accept_param(true),
       URL(init_URL)
      {
        
      }
};

typedef vector<URIEntry> URIDict;

class ApachePayloadServer: public PayloadServer
{
  friend class PayloadScraper; /* We need the url retrieving capabilities in
                            PayloadScraper*/
 protected:
  string _database_filename;
  string _apache_host_name;
  
  const unsigned long c_max_buffer_size;
  CURL* _curl_obj; //this is used to communicate with http server

  //This is too keep the dict in sync between client and server
  uint8_t _uri_dict_mac[SHA256_DIGEST_LENGTH];

  /**
     re-computes the sha256 of the uri_dict and store it in _uri_dict_mac

     @return a pointer to the sha256 hash buffer
     
  */
  const uint8_t* compute_uri_dict_mac();

  //Cache stuff
  static const size_t c_PAYLOAD_CACHE_ELEMENT_CAPACITY = 500;
  /**
     LRU cache to prevent out of memory when there are lots of payload
     on the server, for now we work with number of payload and can 
     be improved to the limit by total size
   */
  PayloadLRUCache<std::string, std::string, ApachePayloadServer, unordered_map> _payload_cache;
  /**
     This function is supposed to be given to the cache class to be used to retrieve the
     the element when it isn't in the hash table

     @param url_hash the sha-1 hash of the url
  */
  string fetch_hashed_url(const string& url_hash);

 public:
  enum PayloadChoiceStrategy {
    c_most_efficient_payload_choice,
    c_random_payload_choice
  } chosen_payload_choice_strategy;
  /*These are used for client side communication. They are 
   public because http_apache_steg_t uses them frequently.
   FIX ME: They need to be protected though*/
  URIDict uri_dict;
  map<string, unsigned long> uri_decode_book;

  const uint8_t* uri_dict_mac()
  {
    return _uri_dict_mac;
  }

  /**
     Computes URIDict object needed as the coding table to communincate with the client side. return false in case of error.
  */
  bool init_uri_dict();

  /**
     Initiate the dictionary by reading its values as text file stored in memory
     It is used by the client to initiate the memory after receiving it from the server.
     @param dict_stream a stream (file/string) that contains the dictionary in            form of url+end-of-line 
     @return ture if successful
  */
  bool init_uri_dict(istream& dict_stream);

  /**
     Stores the url dict in a stringstream object. This is used in computing
     the sha256 of dict as well as for sending it to the client side.

     @param dict_stream the stringstream object that is going to store the
            dict in file format
  */
  void export_dict(iostream& dict_stream);

  /**
     stores the dict in a file for later use by client side.

     @param dict_buf point to the memory buffer containing the dictionary as a set of url seperated by end of line.
     @param dict_buf_size size of dict_buf
     @param 
  */
  bool store_dict(char* dict_buf, size_t dict_buf_size);

  /**
     The constructor reads the payload database prepared by scraper
     and initialize the payload table.
    */
  ApachePayloadServer(MachineSide init_side, const string& database_filename, const string& cover_server, const string& cover_list); 

  /** virtual functions */
  virtual unsigned int find_client_payload(char* buf, int len, int type);
  virtual int get_payload (int contentType, int cap, char** buf, int* size, double noise2signal = 0, std::string* payload_id_hash = NULL);

  /**
     Gets \0 ended uri char* and determines its type based on
     the extension of the file requested in the url

     @param url the url to determine its type.
     @param buflen is not used. Only for compatibility.
     @return the type of url
  */
  virtual int find_url_type(const char* url);

  /**
     turn on the corrupted flag for the payload identified by payload_id_hash
     
     by default the payload server doesn't support disqualification and just
     returns. The payload server which support disqualification need to 
     overload this function.
   */
  virtual void disqualify_payload(const std::string& payload_id_hash) {
    _payload_database.payloads[payload_id_hash].corrupted = true;

    //if the disqualified cover is the highest capacity cover then we need to
    //decrease the max capacity
    _payload_database.adjust_type_max_capacity(payload_id_hash);
  }

  /** 
      Destructor to clean up curl
  */
  ~ApachePayloadServer();

};

#endif
