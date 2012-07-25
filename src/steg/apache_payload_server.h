#ifndef _APACHE_PAYLOAD_SERVER_H
#define _APACHE_PAYLOAD_SERVER_H

#include <openssl/sha.h> 

#include "payload_server.h"

class ApachePayloadServer: public PayloadServer
{
  friend PayloadScraper; /* We need the url retrieving capabilities in
                            PayloadScraper*/
 protected:
  string _database_filename;
  string _apache_host_name = "127.0.0.1";
  
  const unsigned long c_max_buffer_size = 1000000;
  CURL* _curl_obj; //this is used to communicate with http server

  //This is too keep the dict in sync between client and server
  uint8_t _uri_dict_mac[SHA256_DIGEST_LENGTH];

  /**
     re-computes the sha256 of the uri_dict and store it in _uri_dict_mac

     @return a pointer to the sha256 hash buffer
     
  */
  const uint8_t* compute_uri_dict_mac();

 public:
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
  ApachePayloadServer(MachineSide init_side, string database_filename09); 

  /** virtual functions */
  virtual unsigned int find_client_payload(char* buf, int len, int type);
  virtual int get_payload (int contentType, int cap, char** buf, int* size);

  /**
     Gets \0 ended uri char* and determines its type based on
     the extension of the file requested in the url

     @param url the url to determine its type.
     @param buflen is not used. Only for compatibility.
     @return the type of url
  */
  virtual int find_url_type(const char* url);

  /** 
      Destructor to clean up curl
  */
  ~ApachePayloadServer();

};

#endif
