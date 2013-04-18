#ifndef _PAYLOAD_SERVER_H
#define _PAYLOAD_SERVER_H
#include <map>
#include <string>

using namespace std; 

//Constants
#define RECV_GOOD 0
#define RECV_INCOMPLETE 0
#define RECV_BAD -1

#define CONN_DATA_REQUEST 1  /* payload packet sent by client */
#define CONN_DATA_REPLY 2    /* payload packet sent by server */

#define NO_NEXT_STATE -1

#define MAX_PAYLOADS 10000
#define MAX_RESP_HDR_SIZE 512

// max number of payloads that have enough capacity from which
// we choose the best fit
#define MAX_CANDIDATE_PAYLOADS 10

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

#define HTTP_MSG_BUF_SIZE 1000000

#define PDF_DELIMITER_SIZE 2
#define PDF_MIN_AVAIL_SIZE 10240
// PDF_MIN_AVAIL_SIZE should reflect the min number of data bytes
// a pdf doc can encode

// specifying the type of contents as an input argument
// for has_eligible_HTTP_content()
#define HTTP_CONTENT_JAVASCRIPT         1
#define HTTP_CONTENT_PDF                2
#define HTTP_CONTENT_SWF                3
#define HTTP_CONTENT_ENCRYPTEDZIP       4
#define HTTP_CONTENT_HTML               5
#define HTTP_CONTENT_JPEG               6


// used by the JavaScript steg module to distinguish two cases in which
// JS may appear in the HTTP msg
// 1) CONTENT-TYPE in HTTP header specifies that the HTTP body is a JS
// 2) CONTENT-TYPE corresponds to HTML, and the HTTP body contains JS
//    denoted by script type for JS
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
  char* url_hash;
  unsigned int type;
  unsigned int capacity;
  unsigned int length;
  string url;

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

typedef map<string, PayloadInfo> PayloadDict;

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
  map<unsigned int, TypeDetail> type_detail;

  /**
   */
  inline void add_payload(char* url_hash, unsigned int type, unsigned int capacity, unsigned int length,  unsigned int url)
  {
    string string_hash(url_hash);
    PayloadInfo new_payload(type, capacity, length, url);
    payloads.insert(pair<string, PayloadInfo>(url_hash, new_payload));

  }

  /** Returns the max capacity of certain type of cover we have in our
      data base

      @param type the type of file that is going to be used as steg
  */
  unsigned int typed_maximum_capacity(int type)
  {
    return type_detail[type].max_capacity;

    /*TODO: I need to look at TracePayloadServer::typed_maximum_capacity to figure out the morale behind the strange division in computing the capacity*/
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
  
 public:
  /** TODO: either change the name (no _) or the access */
  PayloadDatabase _payload_database;

  /** Construtor needs to init the side the least */
  PayloadServer(MachineSide init_side)
    {
      _side = init_side;
    }
  
  //virtual ~PayloadServer();

  virtual unsigned int find_client_payload(char* buf, int len, int type) = 0;

  virtual int get_payload (int contentType, int cap, char** buf, int* size) = 0;

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

  int gen_response_header(char* content_type, int gzip, int length,
                          char* buf, int buflen);
#endif
