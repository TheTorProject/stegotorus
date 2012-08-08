#ifndef _APACHE_PAYLOAD_SERVER_H
#define _APACHE_PAYLOAD_SERVER_H

#include "payload_server.h"

class PayloadScraper; /* Just tell ApachePayloadServer that such a
                        class exists */

class URIEntry
{
  public:
    string URL;
    bool accept_param = true; /*This is to discriminate between types like html
                                vs cgi, js, etc, but for now I'm not using it
                              */
    URIEntry(string init_URL)
      :URL(init_URL)
      {
        
      }
};

typedef vector<URIEntry> URIDict;

class ApachePayloadServer: public PayloadServer
{
  friend PayloadScraper; /* We need the url retrieving capabilities in
                            PayloadScraper*/
 protected:
  string _database_filename;
  
  const unsigned long c_max_buffer_size = 10000000;
  CURL* _curl_obj; //this is used to communicate with http server

  /** 
      Uses curl to fetch the raw POST body from Apache to be used as payload.
      return the actual length of the payload or zero in the case of error.

      @param url the url of the requested file
      @param payload_length the length of the requested file this is equal to
      the size of allocated memory for the buf
      @param buf the alocated memory to store the POST reply
   */
  unsigned long fetch_url_raw(string url, unsigned long payload_length, stringstream& buf);

  /**
     The call back function that is called when curl request a file from
     the webserver (libcurl calls it write_data for some reason). It has to be static to be able to send it as cb
  */
  static size_t read_data_cb(void *buffer, size_t size, size_t nmemb, void *userp);


 public:
  /**
     Computes URIDict object needed as the coding table to communincate with the client side. return false in case of error.
  */
  bool init_uri_dict();

  /*These are used for client side communication*/
  URIDict uri_dict;
  map<string, unsigned long> uri_decode_book;

  /**
     The constructor reads the payload database prepared by scraper
     and initialize the payload table.
    */
  ApachePayloadServer(MachineSide init_side, string database_filename); 

  /** virtual functions */
  unsigned int find_client_payload(char* buf, int len, int type);
  int get_payload (int contentType, int cap, char** buf, int* size);
  

  /** 
      Destructor to clean up curl
  */
  ~ApachePayloadServer();

};

#endif
