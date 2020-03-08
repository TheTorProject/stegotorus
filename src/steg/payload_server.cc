/* Copyright 2011, 2012 SRI International
 * Copryight 2012, vmon
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "payload_server.h"
#include <ctype.h>
#include <time.h>

const vector<uint8_t> PayloadServer::c_empty_payload;

bool operator< (const EfficiencyIndicator &lhs, const EfficiencyIndicator& rhs) {
    return (lhs.length < rhs.length);
}
    
unsigned int
PayloadServer::capacityPDF (char* buf, int len) {
  char *hEnd, *bp, *streamStart, *streamEnd;
  int cnt=0;
  int size;

  // jump to the beginning of the body of the HTTP message
  hEnd = strstr(buf, "\r\n\r\n");
  if (hEnd == NULL) {
    // cannot find the separator between HTTP header and HTTP body
    return 0;
  }
  bp = hEnd + 4;

  while (bp < (buf+len)) {
     streamStart = strInBinary("stream", 6, bp, (buf+len)-bp);
     if (streamStart == NULL) break;
     bp = streamStart+6;
     streamEnd = strInBinary("endstream", 9, bp, (buf+len)-bp);
     if (streamEnd == NULL) break;
     // count the number of char between streamStart+6 and streamEnd
     size = streamEnd - (streamStart+6) - 2; // 2 for \r\n before streamEnd
     if (size > 0) {
       cnt = cnt + size;
       //log_debug("capacity of pdf increase by %d", size);
     }
     bp += 9;
  }
  return cnt;
}


/*
 * capacitySWF is just mock function 
  returning the len just for the sake of harmonizing
  the capacity computation. We need to make payload
  types as a children of all classes.
 */
unsigned int 
PayloadServer::capacitySWF(char* buf, int len)
{
  (void)buf;
  return len;
}

/*
 * capacityJS is designed to call capacityJS3 
 */
// unsigned int 
// PayloadServer::capacityJS (char* buf, int len) {

//   int mode = has_eligible_HTTP_content(buf, len, HTTP_CONTENT_JAVASCRIPT);
//   if (mode != CONTENT_JAVASCRIPT)
//     mode = has_eligible_HTTP_content(buf, len, HTTP_CONTENT_HTML);
  
//   if (mode != CONTENT_HTML_JAVASCRIPT && mode != CONTENT_JAVASCRIPT)
//     return 0;

//   size_t cap = capacityJS3(buf, len, mode);

//   if (cap <  JS_DELIMITER_SIZE)
//     return 0;
    
//   return (cap - JS_DELIMITER_SIZE)/2;
// }


/* first line is of the form....
   GET /XX/XXXX.swf[?YYYY] HTTP/1.1\r\n
*/


int 
PayloadServer::find_uri_type(const char* buf_orig, int buflen) {

  std::string buf(buf_orig, buflen);

  if (strncmp(buf.c_str(), "GET", 3) != 0
      && strncmp(buf.c_str(), "POST", 4) != 0) {
    log_debug("Unable to determine URI type. Not a GET/POST requests.\n");
    return -1;
  }

  size_t uri_pos = buf.find(' ');

  if (uri_pos == std::string::npos) {
    log_debug("Invalid URL\n");
    return -1;
  }

  uri_pos += 1;

  size_t uri_end_pos = buf.find('?', uri_pos);
  if (uri_end_pos == std::string::npos)
    uri_end_pos = buf.find(' ', uri_pos);
  
  if (uri_end_pos == std::string::npos) {
    log_debug("unterminated uri: %s", buf.substr(uri_pos).c_str());
    return -1;
  }

  size_t filename_pos = buf.rfind('/', uri_end_pos);

  if (filename_pos == std::string::npos) {
    log_debug("no / in url: %s", buf.substr(uri_pos, uri_end_pos - uri_pos + 1).c_str());
    return -1;
  }

  std::string filename = buf.substr(filename_pos, uri_end_pos - filename_pos); //we don't want to include
  //the uri end character ' ' or '?' in the filename
  size_t ext_pos = filename.find('.');
  //if an extension is found then there is a dot otherwise it is null
  log_debug("payload extension is %s", filename.substr(ext_pos+1).c_str());
  return (ext_pos == std::string::npos) ?
    extension_to_content_type("") :    
    extension_to_content_type(filename.substr(ext_pos+1).c_str());

}

/**
   get the file extension and return the numerical contstant representing the content type

   @param extension file extension such as html, htm, js, jpg, 

   @return content type constant or -1 if not found, a null extensions is considered as html type
*/
int 
PayloadServer::extension_to_content_type(const string& extension)
{
  //no extension preceived as html
  string lowered_extension = extension.empty() ? "html" : extension;;
  
  transform(lowered_extension.begin(), lowered_extension.end(), lowered_extension.begin(), ::tolower);
  auto extension_content_type = extension_to_content_type_map.find(lowered_extension);
  return (extension_content_type != extension_to_content_type_map.end()) ? extension_content_type->second : -1;

}

/**
   set the set of active type whose corresponding steg mode are permitted to use 
   this is mostly for testing specific steg types

   @param active_steg_mod_list comma separated string set of active steg mod indicated by extension. currently 
   only one active steg is supported

   @return true if successful false if there was a problem with the indicated type.
*/
bool PayloadServer::set_active_steg_mods(const std::string& active_steg_mod_list)
{
  //TODO: only one steg extension is accepted here. multiple steg type
  //activation should be supported.
  int requested_steg_type =  extension_to_content_type(active_steg_mod_list.c_str());

  if (requested_steg_type == -1)
    return false;
  
  active_steg_mods.push_back(requested_steg_type);

  return true;

}

int
PayloadServer::parse_client_headers(char* inbuf, char* outbuf, int len) {
  // client-side
  // remove Host: field
  // remove referrer fields?

  char* ptr = inbuf;
  int outlen = 0;

  while (1) {
    // char* end = strstr(ptr, "\r\n", len - (ptr - inbuf));
    char* end = strstr(ptr, "\r\n");
    if (end == NULL) {
      fprintf(stderr, "invalid client header %d %d %s \n PTR = %s\n", len, (int) (len - (ptr - inbuf)), inbuf, ptr);
      // fprintf(stderr, "HERE %s\n", ptr);
      break;
    }

    if (!strncmp(ptr, "Host:", 5) ||
	!strncmp(ptr, "Referer:", 8) ||
	!strncmp(ptr, "Cookie:", 7)) {
      goto next;
    }

    memcpy(outbuf + outlen, ptr, end - ptr + 2);
    outlen += end - ptr + 2;

  next:
    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }
  
  return outlen;

  // server-side
  // fix date fields
  // fix content-length



}




