/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _PAYLOADS_H
#define _PAYLOADS_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <ctype.h>


/* three files:
   server_data, client data, protocol data
*/

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



typedef int SID;
typedef short PacketType;
typedef short StateFlag;

#define TYPE_SERVICE_DATA 0x1
#define TYPE_HTTP_REQUEST 0x2
#define TYPE_HTTP_RESPONSE 0x4
#define BEGIN_STATE_FLG 0x1
#define END_STATE_FLG 0x2


/* struct for reading in the payload_gen dump file */
typedef struct {
  PacketType ptype;
  int length;
  ushort port; /* network format */
}pentry_header;




typedef struct service_state {
  SID id;
  PacketType data_type;
  SID next_state;
  //  double* probabilities;
  StateFlag flg;
  int dir;
}state;

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


#define HTTP_MSG_BUF_SIZE 100000

void load_payloads(payloads& pl, const char* fname);
unsigned int find_client_payload(payloads& pl, char* buf, int len, int type);
unsigned int find_server_payload(payloads& pl, char** buf, int len, int type, int contentType);

int init_JS_payload_pool(payloads& pl, int len, int type, int minCapacity);
int init_SWF_payload_pool(payloads& pl, int len, int type, int minCapacity);
int init_PDF_payload_pool(payloads& pl, int len, int type,int minCapacity);
int init_HTML_payload_pool(payloads& pl, int len, int type, int minCapacity);


int get_next_payload (payloads& pl, int contentType, char** buf, int* size, int* cap);
int get_payload (payloads& pl, int contentType, int cap, char** buf, int* size);

int has_eligible_HTTP_content (char* buf, int len, int type);
int fixContentLen (char* payload, int payloadLen, char *buf, int bufLen);
void gen_rfc_1123_date(char* buf, int buf_size);
void gen_rfc_1123_expiry_date(char* buf, int buf_size);
int parse_client_headers(char* inbuf, char* outbuf, int len);
int skipJSPattern (char *cp, int len);
int isalnum_ (char c);
int offset2Alnum_ (char *p, int range);
int offset2Hex (char *p, int range, int isLastCharHex);
unsigned int capacityJS3 (char* buf, int len, int mode);
unsigned int get_max_JS_capacity(void);
unsigned int get_max_HTML_capacity(void);

char * strInBinary (const char *pattern, unsigned int patternLen, const char *blob, unsigned int blobLen);


unsigned int capacityPDF (char* buf, int len);
unsigned int get_max_PDF_capacity(void);
int find_content_length (char *hdr, int hlen);
int find_uri_type(char* buf, int size);

int gen_response_header(char* content_type, int gzip, int length, char* buf, int buflen);

#endif
