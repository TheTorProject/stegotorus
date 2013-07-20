/* Copyright 2012 vmon 
 * See LICENSE for other credits and copying information 
 */
#ifndef _TRACE_PAYLOAD_SERVER_H
#define _TRACE_PAYLOAD_SERVER_H

#include "payload_server.h"

/* struct for reading in the payload_gen dump file */
/* Our PayloadInfo class in payload_server should become universal enough 
   so we do not need following structs. */
struct pentry_header {
  PacketType ptype;
  int length;
  ushort port; /* network format */
};

struct service_state {
  SID id;
  PacketType data_type;
  SID next_state;
  //  double* probabilities;
  StateFlag flg;
  int dir;
};

struct payloads {
  int initTypePayload[MAX_CONTENT_TYPE];
  int typePayloadCount[MAX_CONTENT_TYPE];
  int typePayload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
  int typePayloadCap[MAX_CONTENT_TYPE][MAX_PAYLOADS];

  unsigned int max_JS_capacity;
  unsigned int max_HTML_capacity;
  unsigned int max_PDF_capacity;

  pentry_header payload_hdrs[MAX_PAYLOADS];
  char* payloads[MAX_PAYLOADS];
  int payload_count;
};

class TracePayloadServer: public PayloadServer
{
 protected:
  /* this should be change to PayloadDatabase type and for now, I leave itas is
     . However, I made it protected meaning that any function that needs to access it should be part of this class. This is necessary so the rest of the code is compatible with different payload server*/
  payloads pl;
  const unsigned long c_max_buffer_size = 1000000;

  /** called by the constructor to load the payloads */
  void load_payloads(const char* fname);

 public:

  /**
     The constructor reads the payload database prepared by scraper
     and initialize the payload table.
    */
  TracePayloadServer(MachineSide init_side, string fname); 

  /**virtual functions */
  unsigned int find_client_payload(char* buf, int len, int type);

  int get_payload (int contentType, int cap, char** buf, int* size, double noise2signal = 0);

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
