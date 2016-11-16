#ifndef _PAYLOAD_SERVER_H
#define _PAYLOAD_SERVER_H
#include <map>
#include <string>
#include <vector>
#include <list>
#include <algorithm>

using namespace std; 

//Constants
#define RECV_GOOD 0
#define RECV_INCOMPLETE 0
#define RECV_BAD -1

#define CONN_DATA_REQUEST 1  /* payload packet sent by client */
#define CONN_DATA_REPLY 2    /* payload packet sent by server */

#define NO_NEXT_STATE -1

#define MAX_PAYLOADS 10000
#define MAX_RESP_HDR_SIZE 8192

// max number of payloads that have enough capacity from which
// we choose the best fit
#define MAX_CANDIDATE_PAYLOADS 100

// jsSteg-specific defines
#define JS_DELIMITER '?'
// a JavaScript delimiter is used to signal the end of encoding
// to facilitate the decoding process
#define JS_DELIMITER_REPLACEMENT '!'
// JS_DELIMITER that exists in the JavaScript before the end of
// data encoding will be replaced by JS_DELIMITER_REPLACEMENT
#define JS_DELIMITER_SIZE 1

// #define JS_MIN_AVAIL_SIZE 2050
#define JS_MIN_AVAIL_SIZE 1026
// JS_MIN_AVAIL_SIZE should reflect the min number of data bytes
// a JavaScript may encapsulate

#define HTML_MIN_AVAIL_SIZE 1026

#define HTTP_MSG_BUF_SIZE 500000
static const  size_t c_MAX_MSG_BUF_SIZE = 131101;

#define SWF_HYPO_CAPACITY HTTP_MSG_BUF_SIZE - MAX_RESP_HDR_SIZE - (SWF_SAVE_FOOTER_LEN + SWF_SAVE_HEADER_LEN + 8 + 512)

#define PDF_DELIMITER_SIZE 2
#define PDF_MIN_AVAIL_SIZE 10240
#define PDF_MAX_AVAIL_SIZE 100000 //added from SRI build...just for testing for now
// PDF_MIN_AVAIL_SIZE should reflect the min number of data bytes
// a pdf doc can encode...ignoring this for now.

// specifying the type of contents as an input argument
// for has_eligible_HTTP_content()
#define HTTP_CONTENT_UNSUPPORTED       -1
#define HTTP_CONTENT_RESERVED           0
#define HTTP_CONTENT_JAVASCRIPT         1
#define HTTP_CONTENT_HTML               2
#define HTTP_CONTENT_PDF                3
#define HTTP_CONTENT_SWF                4
#define HTTP_CONTENT_ENCRYPTEDZIP       5
#define HTTP_CONTENT_JPEG               6
#define HTTP_CONTENT_PNG                7
#define HTTP_CONTENT_GIF                8

//I could not find a single class that made
//sense to put this in it so let it be global
const unsigned int c_no_of_steg_protocol = 8;

// used by the JavaScript steg module to distinguish two cases in which
// JS may appear in the HTTP msg
// 1) CONTENT-TYPE in HTTP header specifies that the HTTP body is a JS
// 2) CONTENT-TYPE corresponds to HTML, and the HTTP body contains JS
//    denoted by script type for JS
//for now the second type is handled via the original non subclassed functions as it is a bit more complex
#define CONTENT_JAVASCRIPT              1
#define CONTENT_HTML_JAVASCRIPT         2

// payloads for specific content type
//
// MAX_CONTENT_TYPE specifies the maximum number of supported content types
// (e.g. HTTP_CONTENT_JAVASCRIPT is a content type)
//
// initTypePayload[x] specifies whether the arrays typePayloadCount and
// typePayloads for content type x
//
// typePayloadCount[x] specifies the number of available payloads for
// content type x
//
// typePayload[x][] contains references to the corresponding entries in
// payload_hdrs[] and payloads[]
//
// typePayloadCap[x][] specifies the capacity for typePayload[x][]

#define MAX_CONTENT_TYPE		11
#define NO_CONTENT_TYPES                 5

typedef int SID;
typedef short PacketType;
typedef short StateFlag;

#define TYPE_SERVICE_DATA 0x1
#define TYPE_HTTP_REQUEST 0x2
#define TYPE_HTTP_RESPONSE 0x4
#define BEGIN_STATE_FLG 0x1
#define END_STATE_FLG 0x2

class PayloadInfo{
 public:
  string url_hash;
  unsigned int type;
  unsigned int capacity;
  unsigned int length;
  string absolute_url;
  string url;
  bool absolute_url_is_absolute; //true if the url contains domain name
  bool corrupted;
  char* cached;
  unsigned int cached_size;

  /** 
      Default constructor
  */
  PayloadInfo()
    :corrupted(false)
    {
      cached = NULL;
      cached_size = 0;
      
    }

};

typedef map<string, PayloadInfo> PayloadDict;

class EfficiencyIndicator
{
 public:
  string url_hash;
  unsigned long length;

  EfficiencyIndicator(string new_hash, unsigned long new_length)
   : url_hash(new_hash), length(new_length)
  {  }

  bool operator<(EfficiencyIndicator rhs) {
    return (length < rhs.length);
  }
};

/** 
    The initiation process needs to fill up the
    fields of this class
*/
class TypeDetail
{
 public:
  unsigned int max_capacity;
  unsigned int count;

  TypeDetail(unsigned int new_max_cap, unsigned int new_count)
    :max_capacity(new_max_cap), count(new_count)
    {
      
    }

  /*we need default constructor*/
  TypeDetail()
    :max_capacity(0), count(0)
    {
      
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
  PayloadDict payloads;
  list<EfficiencyIndicator> sorted_payloads;

  map<unsigned int, TypeDetail> type_detail;

  /** Returns the max capacity of certain type of cover we have in our
      data base

      @param type the type of file that is going to be used as steg
  */
  unsigned int typed_maximum_capacity(int type)
  {
    return type_detail[type].max_capacity;

    /*TODO: I need to look at TracePayloadServer::typed_maximum_capacity to figure out the morale behind the strange division in computing the capacity*/
  }

  /**
   reduce the maximum capacity of a specific type in case the cover with
   maximum capacity get marked as corrupted 

   @param payload_id_hash id_hash of the payload which got corrupted/became unavailable

  */
  void adjust_type_max_capacity(const std::string&  payload_id_hash ){
      //see if adjustment is needed.
    if (payloads[payload_id_hash].corrupted &&
        payloads[payload_id_hash].capacity >= typed_maximum_capacity(payloads[payload_id_hash].type)) {
      //then we need to probably decrease the maximum capacity
      const unsigned int affected_type = payloads[payload_id_hash].type;
      //searching for new max capacity among all eligible covers
      type_detail[affected_type].max_capacity = 0;
      for(auto cur_payload = payloads.begin(); cur_payload != payloads.end(); cur_payload++)
        {
          if ((cur_payload->second.type == affected_type) &&
              (!cur_payload->second.corrupted) &&
              (cur_payload->second.capacity > type_detail[affected_type].max_capacity)) {
            type_detail[affected_type].max_capacity = cur_payload->second.capacity;
          }
        }
    }
  }
  
};

/* The payload server needs to know which side we are at */
enum MachineSide
  {
    client_side,
    server_side
  };

class PayloadServer
{
 protected:
  MachineSide _side;

  //list of active steg mod, if the list is empty everything is active
  std::vector<unsigned int> active_steg_mods;
  
 public:
  /** TODO: either change the name (no _) or the access */
  PayloadDatabase _payload_database;

  /** Construtor needs to init the side the least */
  PayloadServer(MachineSide init_side)
    {
      _side = init_side;
    }
  
  virtual ~PayloadServer(){};

  /**
   get the file extension and return the numerical contstant representing the content type

   @param extension file extension such as html, htm, js, jpg, 

   @return content type constant or -1 if not found, a null extensions is considered as html type
  */
  int extension_to_content_type(const char* extension);

  virtual unsigned int find_client_payload(char* buf, int len, int type) = 0;

  /**
     @param payload_id_hash if payload_id_has is not NULL, then the function
            copy the payload identifier hash into for further reference like
            disqualifiying the payload
   */
  virtual int get_payload (int contentType, int cap, char** buf, int* size, double noise2signal=0, std::string* payload_id_hash = NULL) = 0;

  /**
     turn on the corrupted flag for the payload identified by payload_id_hash
     
     by default the payload server doesn't support disqualification and just
     returns. The payload server which support disqualification need to 
     overload this function.
   */
  virtual void disqualify_payload(const std::string& payload_id_hash) {
    (void) payload_id_hash; //nop
    return;
  }

  virtual int find_uri_type(const char* buf, int size);

  /** return the side for which, the payload_server is initialized */
  MachineSide side()
  {
    return _side;

  }

  static unsigned int capacityJS3 (char* buf, int len, int mode);
  static unsigned int get_max_JS_capacity(void);
  static unsigned int get_max_HTML_capacity(void);

  static unsigned int capacityPDF (char* buf, int len);
  static unsigned int get_max_PDF_capacity(void);

  /* These are added to make payload_scraper works for now.
     The plan is to make each type of steg payload a class
  */
  static unsigned int capacityJS(char* buf, int len);
  static unsigned int capacitySWF(char* buf, int len);

  /* Payload manipulation tools */

  /**
     TODO: IMPLEMENT
     Gets an HTTP Response header and change the reponse size
     to the new size.

     @return the length of new header

     see also 
  size_t alter_length_in_response_header(uint8_t* original_header, size_t original_header_length, ssize_t new_content_length, uint8_t new_header[]) in file_steg.h
   */
  size_t adjust_header_size(char* original_header, size_t original_length,                            char* newHeader);

  /**
     set the set of active type whose corresponding steg mode are permitted to use 
     this is mostly for testing specific steg types

     @param active_steg_mod_list comma separated string set of active steg mod indicated by extension. currently 
            only one active steg is supported

     @return true if successful false if there was a problem with the indicated type.
   */
  bool set_active_steg_mods(const std::string& active_steg_mod_list);

  /**
     return true if the content type has a steg mod assigned to it and is 
     activated by user  or if user has not been restrict to any content type

     @param content_type the content type to be check if is allowed to be served

     @return true if the payload server is supposed to serve this type of content 
     otherwise false
  */
  bool  is_activated_valid_content_type(int content_type) {
    return (
            ((content_type > 0 && content_type < MAX_CONTENT_TYPE)) && //validity
            ((active_steg_mods.empty()) || //user hasn't restricted or
             (std::find(active_steg_mods.begin(), active_steg_mods.end(), content_type) != active_steg_mods.end()))
            ); //or it is part of the activated
            //mods
  }
    
      
};


  /** Moved from payloads.c without a touch. needs clean up */
  char * strInBinary (const char *pattern, unsigned int patternLen,
                      const char *blob, unsigned int blobLen);
  int find_content_length (char *hdr, int hlen);

  int has_eligible_HTTP_content (char* buf, int len, int type);
  int fixContentLen (char* payload, int payloadLen, char *buf, int bufLen);
  void gen_rfc_1123_date(char* buf, int buf_size);
  void gen_rfc_1123_expiry_date(char* buf, int buf_size);
  int parse_client_headers(char* inbuf, char* outbuf, int len);
  int skipJSPattern (char *cp, int len);
  int isalnum_ (char c);
  int offset2Alnum_ (char *p, int range);
  int offset2Hex (char *p, int range, int isLastCharHex);
  int encodeHTTPBody(char *data, char *jTemplate, char *jData, unsigned int dlen,
                   unsigned int jtlen, unsigned int jdlen, int mode);

int isxString(char *str);

int isGzipContent (char *msg);

int findContentType (char *msg);

int decodeHTTPBody (char *jData, char *dataBuf, unsigned int jdlen,
                    unsigned int dataBufSize, int *fin, int mode);

  int gen_response_header(char* content_type, int gzip, int length,
                          char* buf, int buflen);
#endif
