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
