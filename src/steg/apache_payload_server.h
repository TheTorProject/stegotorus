#ifndef _APACHE_PAYLOAD_SERVER_H
#define _APACHE_PAYLOAD_SERVER_H

#include "payload_server.h"
#include "payloads.h"

class ApachePayloadServer: public PayloadServer
{
 protected:
  string _database_filename;
  
  const unsigned long c_max_buffer_size = 1000000;
  CURL* _curl_obj; //this is used to communicate with http server

  /** Uses curl to fetch the raw POST body from Apache to be used as payload.
      return the actual length of the payload or zero in the case of error.

      @param url the url of the requested file
      @param payload_length the length of the requested file this is equal to the size of allocated memory for the buf
      @param buf the alocated memory to store the POST reply
   */
  unsigned long fetch_url_raw(string url, unsigned long payload_length, char* buf);

 public:

  /**
     The constructor reads the payload database prepared by scraper
     and initialize the payload table.
    */
  ApachePayloadServer(string database_filename); 
  unsigned int find_client_payload(struct payloads& pl, char* buf, int len, int type);

  int get_payload (struct payloads& pl, int contentType, int cap, char** buf, int* size);

};

#endif
