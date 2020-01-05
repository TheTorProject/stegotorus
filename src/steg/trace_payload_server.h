/* Copyright 2012 vmon 
 * See LICENSE for other credits and copying information 
 */
#ifndef _TRACE_PAYLOAD_SERVER_H
#define _TRACE_PAYLOAD_SERVER_H

#include "payload_server.h"
//#include "http_steg_mods/pdfSteg.h"
/* struct for reading in the payload_gen dump file */
/* Our PayloadInfo class in payload_server should become universal enough 
   so we do not need following structs. */
struct pentry_header {
  PacketType ptype;
  int length; 
  uint16_t port; /* network format */
};

struct service_state {
  StateID id;
  PacketType data_type;
  StateID next_state;
  //  double* probabilities;
  StateFlag flg;
  int dir;
};

/**
   This struct keeps global information about all payloads
   across types as well as information about each payload 
   and the payload body. 
 */
struct payloads {
  int initTypePayload[MAX_CONTENT_TYPE];
  int typePayloadCount[MAX_CONTENT_TYPE];
  int typePayload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
  int typePayloadCap[MAX_CONTENT_TYPE][MAX_PAYLOADS];

  unsigned int max_JS_capacity;
  unsigned int max_HTML_capacity;
  unsigned int max_PDF_capacity;

  pentry_header payload_hdrs[MAX_PAYLOADS]; //stores properties of each payload such as type and size.
  std::vector<uint8_t> payloads[MAX_PAYLOADS];
  int payload_count;
};

class TracePayloadServer: public PayloadServer
{
 protected:
  /* this should be change to PayloadDatabase type and for now, I leave itas is
     . However, I made it protected meaning that any function that needs to access it should be part of this class. This is necessary so the rest of the code is compatible with different payload server*/
  payloads pl;
  const unsigned long c_max_buffer_size;


  static int fixContentLen (char* payload, int payloadLen, char *buf, int bufLen);

  /** called by the constructor to load the payloads */
  void load_payloads(const char* fname);

  /**
     returns 1 check the validity of the payload as a usable HTTP response

 * has_eligible_HTTP_content() identifies if the input HTTP message 
 * contains a specified type of content, used by a steg module to
 * select candidate HTTP message as cover traffic
 */

// for JavaScript, there are two cases:
// 1) If Content-Type: has one of the following values
//       text/javascript 
//       application/x-javascript
//       application/javascript
// 2) Content-Type: text/html and 
//    HTTP body contains <script type="text/javascript"> ... </script>
// #define CONTENT_JAVASCRIPT		1 (for case 1)
// #define CONTENT_HTML_JAVASCRIPT	2 (for case 2)
//
// for pdf, we look for the msgs whose Content-Type: has one of the
// following values
// 1) application/pdf
// 2) application/x-pdf
// 
  static int has_eligible_HTTP_content (char* buf, int len, int type);
  
public:

  /**
     The constructor reads the payload database prepared by scraper
     and initialize the payload table.
    */
  TracePayloadServer(MachineSide init_side, string fname); 

  /**virtual functions */
  unsigned int find_client_payload(char* buf, int len, int type);

  /**
     Implementation of the abstract function PayloadServer::get_payload
  */
  virtual const std::vector<uint8_t>& get_payload (int contentType, int cap, double noise2signal = 0, std::string* payload_id_hash = NULL);

  /** Moved untouched from payloads.c */
  int init_JS_payload_pool(int len, int type, int minCapacity);
  int init_SWF_payload_pool(int len, int type, int minCapacity);
  int init_PDF_payload_pool(int len, int type,int minCapacity);
  int init_HTML_payload_pool(int len, int type, int minCapacity);

  /** Returns the max capacity of certain type of cover we have in our
      data base

      @param type the type of file that is going to be used as steg
  */
  unsigned int typed_maximum_capacity(int type);

};

#endif
