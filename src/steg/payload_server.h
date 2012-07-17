#ifndef _PAYLOAD_SERVER_H
#define _PAYLOAD_SERVER_H
#include <map>
#include <string>

using namespace std; 
#include "payloads.h"

class PayloadInfo{
 public:
  char* url_hash;
  unsigned int type;
  unsigned int capacity;
  unsigned int length;
  unsigned int url;

  /**
     constructor fills up the elements  
  */
  PayloadInfo(unsigned int type, unsigned int capacity, unsigned int length,  unsigned int url);

  /** 
      Default constructor
  */
  PayloadInfo()
    {
      url_hash = NULL;
    }

};

class PayloadDatabase{
 public:
  //int initTypePayload[MAX_CONTENT_TYPE];
  //int typePayloadCount[MAX_CONTENT_TYPE];
  //int typePayload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
  //int typePayloadCap[MAX_CONTENT_TYPE][MAX_PAYLOADS];

  //unsigned int max_JS_capacity;
  //unsigned int max_HTML_capacity;
  //unsigned int max_PDF_capacity;

  //pentry_header payload_hdrs[MAX_PAYLOADS];
  map<string, PayloadInfo> payloads;

  /**
   */
  inline void add_payload(char* url_hash, unsigned int type, unsigned int capacity, unsigned int length,  unsigned int url)
  {
    string string_hash(url_hash);
    PayloadInfo new_payload(type, capacity, length, url);
    payloads.insert(pair<string, PayloadInfo>(url_hash, new_payload));

  }

};

class PayloadServer
{
 protected:
  PayloadDatabase _payload_database;

 public:
  virtual unsigned int find_client_payload(payloads& pl, char* buf, int len, int type);

  virtual int get_payload (payloads& pl, int contentType, int cap, char** buf, int* size);

};

#endif
