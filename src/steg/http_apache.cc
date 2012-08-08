#include <event2/buffer.h>
#include <curl/curl.h>
#include <vector>
#include <iostream>

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include "rng.h"


#include "payload_server.h"
#include "trace_payload_server.h"
#include "apache_payload_server.h"

#include "cookies.h"
#include "swfSteg.h"
#include "pdfSteg.h"
#include "jsSteg.h"
#include "base64.h"
#include "b64cookies.h"

#include "http.h"

using namespace std;

namespace  {
  struct http_apache_steg_config_t : http_steg_config_t
  {
    ApachePayloadServer* _apache_payload_server; //We need a payload server to process transmit or receive.

    STEG_CONFIG_DECLARE_METHODS(http_apache);
  };

  struct http_apache_steg_t : http_steg_t
  {

    const size_t c_min_uri_length = 1;
    const size_t c_max_uri_length = 2000; //Unofficial cap

    CURL* _curl_obj; //this is used to communicate with http server
     
    unsigned long uri_byte_cut; /* The number of byte of the message that
                                    can be stored in url */

    http_apache_steg_config_t* _confs;

     /**
        constructors and destructors taking care of curl initialization and
        clean-up
     */
    STEG_DECLARE_METHODS(http_apache);

    http_apache_steg_t(http_apache_steg_config_t *cf, conn_t *cn);

     /* Client side communication */
     int init_uri_dit(evbuffer *dict_buff)
     {
       (void)dict_buff;
       return 0;
     }

     /** 
         Uses the server side database to init the URI dictionary. This is only for test purpose. return true if it succeeds

     */
     bool init_uri_dict_for_test();
       
     /**
        A function for testing purpose that reads the uri dictionary 
        from a local file. In real life, the dictionary should be 
        passed using the steg channel on the net. returns 0 in case of no 
        error.

        @param uri_dict_filename name of the file that containt the
               info locally. This is simply list of 
               file names on the server
     */
     int load_uri_dict(string uri_dict_filename);

     virtual int http_client_uri_transmit (struct evbuffer *source, conn_t *conn);
     virtual int http_server_receive(conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

     virtual int http_server_receive_cookie(char* p, struct evbuffer *dest);
     virtual int http_server_receive_uri(char *p, struct evbuffer *dest);
  };
}

STEG_DEFINE_MODULE(http_apache);

http_apache_steg_config_t::http_apache_steg_config_t(config_t *cfg)
  : http_steg_config_t(cfg)
{
  is_clientside = (cfg->mode != LSN_SIMPLE_SERVER);
  string payload_filename;
  payload_filename = "traces/payload_list.txt";
  
  _apache_payload_server = new ApachePayloadServer(is_clientside ? client_side : server_side, payload_filename);

}

http_apache_steg_config_t::~http_apache_steg_config_t()
{
  //delete payload_server; maybe we don't need it

}

steg_t *
http_apache_steg_config_t::steg_create(conn_t *conn)
    {

  return new http_apache_steg_t(this, conn);
}


http_apache_steg_t::http_apache_steg_t(http_apache_steg_config_t *cf, conn_t *cn)
  : http_steg_t((http_steg_config_t*)cf, cn), _confs(cf)
{

  if (!_confs->_apache_payload_server)
    log_abort("Payload server is not initialized.");

    if (!(_curl_obj = curl_easy_init()))
      log_abort("Failed to initiate the curl object.");

    /* For test only */
    init_uri_dict_for_test();
}

int
http_apache_steg_t::http_client_uri_transmit (struct evbuffer *source, conn_t *conn)
{

  size_t sbuflen = evbuffer_get_length(source);

  char* data;
  char* data2 = (char*) xmalloc (sbuflen*4);
  size_t len;

  // '+' -> '-', '/' -> '_', '=' -> '.' per
  // RFC4648 "Base 64 encoding with RL and filename safe alphabet"
  // (which does not replace '=', but dot is an obvious choice; for
  // this use case, the fact that some file systems don't allow more
  // than one dot in a filename is irrelevant).

  //First make the evbuffer data like a normal buffor
  data = (char*) evbuffer_pullup(source, sbuflen);
  if (!data) {
    log_debug("evbuffer_pullup failed");
    return -1;
  }

  /*First we need to cut the first few bytes into the url */
  unsigned long url_index = 0;
  //memcpy((void*)&url_index, data, uri_byte_cut); this machine dependent
  for(unsigned int i = 0; i < uri_byte_cut && i < sbuflen; i++)
    {
      url_index *=256;
      url_index += (unsigned char) data[i];
    }
  
  string chosen_url= _confs->_apache_payload_server->uri_dict[url_index].URL;

  log_debug("%s is chosen as the url", chosen_url.c_str());

  string uri_to_send("http://");
  if (sbuflen > uri_byte_cut)
    {
      sbuflen -= uri_byte_cut;
      data += uri_byte_cut;

      //Now we encode the rest in a paramter in the uri
      base64::encoder E(false, '-', '_', '.');

      memset(data2, 0, sbuflen*4);
      len  = E.encode(data, sbuflen, data2);
      len += E.encode_end(data2+len);

      uri_to_send += conn->peername;
      uri_to_send += "/"+ chosen_url + "?q=" + data2;

      if (uri_to_send.size() > c_max_uri_length)
        {
          log_debug("%lu too big to be send in uri", uri_to_send.size());
            return -1;
        }
    }
  else
    {
      //the buffer is too short we need to indicate the number
      //bytes. But this probably never happens
      sprintf(data2,"%lu", sbuflen);
      uri_to_send = chosen_url + "?p=";
      uri_to_send += sbuflen;

    }
  
  //now we are using curl to send the request
  curl_easy_setopt(_curl_obj, CURLOPT_URL, uri_to_send.c_str());
  CURLcode res = curl_easy_perform(_curl_obj);

  if (res == CURLE_OK)
    {
      evbuffer_drain(source, sbuflen);
      conn->cease_transmission();
      have_transmitted = 1;
      return 0;
    }
  else
    {
      log_debug("Error in requesting the uri. CURL Error %i", res);
      return -1;
    }
}

int
http_apache_steg_t::http_server_receive(conn_t *conn, struct evbuffer *dest, struct evbuffer* source) {

  char* data;
  int type;

  do {
    struct evbuffer_ptr s2 = evbuffer_search(source, "\r\n\r\n", sizeof ("\r\n\r\n") -1 , NULL);
    char *p;

    //int cookie_mode = 0;

     if (s2.pos == -1) {
      log_debug(conn, "Did not find end of request %d",
                (int) evbuffer_get_length(source));
      return RECV_INCOMPLETE;
    }

     log_debug(conn, "SERVER received request header of length %d", (int)s2.pos);

    data = (char*) evbuffer_pullup(source, s2.pos+4);

    if (data == NULL) {
      log_debug(conn, "SERVER evbuffer_pullup fails");
      return RECV_BAD;
    }

    data[s2.pos+3] = 0;

    type = config->payload_server->find_uri_type((char *)data, s2.pos+4);

    if (strstr((char*) data, "Cookie") != NULL) {
      p = strstr((char*) data, "Cookie:") + sizeof "Cookie: "-1;
      //cookie_mode = 1;
      if (http_server_receive_cookie(p, dest) == RECV_BAD)
        return RECV_BAD;
    }
    else
      {
        p = data + sizeof "GET /" -1;
        http_server_receive_uri(p, dest);
      }

    evbuffer_drain(source, s2.pos + sizeof("\r\n\r\n") - 1);
  } while (evbuffer_get_length(source));

  have_received = 1;
  type = type;

  // FIXME: should decide whether or not to do this based on the
  // Connection: header.  (Needs additional changes elsewhere, esp.
  // in transmit_room.)
  conn->expect_close();

  conn->transmit_soon(100);
  return RECV_GOOD;
}

int http_apache_steg_t::http_server_receive_cookie(char* p, evbuffer* dest)
{
    char outbuf[MAX_COOKIE_SIZE * 3/2];
    char outbuf2[MAX_COOKIE_SIZE];
    char *pend;

    size_t sofar;

    log_debug("Cookie: %s", p);
    pend = strstr(p, "\r\n");
    log_assert(pend);
    if (pend - p > MAX_COOKIE_SIZE * 3/2)
      log_abort(conn, "cookie too big: %lu (max %lu)",
                (unsigned long)(pend - p), (unsigned long)MAX_COOKIE_SIZE);

    memset(outbuf, 0, sizeof(outbuf));
    size_t cookielen = unwrap_b64_cookies(outbuf, p, pend - p);

    base64::decoder D('-', '_', '.');
    memset(outbuf2, 0, sizeof(outbuf2));
    sofar = D.decode(outbuf, cookielen+1, outbuf2);

    if (sofar <= 0)
      log_warn(conn, "base64 decode failed\n");

    if (sofar >= MAX_COOKIE_SIZE)
      log_abort(conn, "cookie decode buffer overflow\n");

    if (evbuffer_add(dest, outbuf2, sofar)) {
      log_debug(conn, "Failed to transfer buffer");
      return RECV_BAD;
    }

    return RECV_GOOD;

}

int http_apache_steg_t::http_server_receive_uri(char *p, evbuffer* dest)
{
    char outbuf[MAX_COOKIE_SIZE * 3/2];
    char outbuf2[MAX_COOKIE_SIZE];
    char *uri_end;

    size_t sofar;

    log_debug("uri: %s", p);
    uri_end = strchr(p, ' ');
    log_assert(uri_end);
    if ((size_t)(uri_end - p) > c_max_uri_length * 3/2)
      log_abort(conn, "uri too big: %lu (max %lu)",
                (unsigned long)(uri_end - p), (unsigned long)c_max_uri_length);

    memset(outbuf, 0, sizeof(outbuf));
    char* url_end = strstr(p, "?");
    unsigned long url_code = _confs->_apache_payload_server->uri_decode_book[string(p, url_end - p)];

    size_t url_meaning_length;
    if (*(url_end + sizeof("?") - 1) == 'p')
      url_meaning_length = atoi(url_end + sizeof("?p") -1);
    else
      url_meaning_length = uri_byte_cut;
    
    for(size_t i = 0; i < url_meaning_length; i++)
    {
      outbuf2[i] = (unsigned char)(url_code % 256);
      url_code /= 256;
    }

    if (url_meaning_length == uri_byte_cut)
      {
        char* param_val_begin = url_end+sizeof("?q=")-1;

        memset(outbuf, 0, sizeof(outbuf));
        size_t cookielen = unwrap_b64_cookies(outbuf, param_val_begin, uri_end - param_val_begin);

         base64::decoder D('-', '_', '.');
        memset(outbuf2+url_meaning_length, 0, sizeof(outbuf2) - url_meaning_length);
        sofar = D.decode(outbuf, cookielen+1, outbuf2+url_meaning_length);

        if (sofar <= 0)
          log_warn(conn, "base64 decode failed\n");

        if (sofar >= c_max_uri_length)
          log_abort(conn, "uri decode buffer overflow\n");
      }

    if (evbuffer_add(dest, outbuf2, sofar)) {
      log_debug(conn, "Failed to transfer buffer");
      return RECV_BAD;
    }

    return RECV_GOOD;
}

http_apache_steg_t::~http_apache_steg_t()
{
    /* always cleanup */ 
    curl_easy_cleanup(_curl_obj);

}

bool http_apache_steg_t::init_uri_dict_for_test()
{
  /* We need to call this explicitly because it is only called by the payload
     server on the server side, but we want to use it on the client side */
  if (!_confs->_apache_payload_server->init_uri_dict())
    return false;

  size_t no_of_uris = _confs->_apache_payload_server->uri_dict.size();
  for(uri_byte_cut = 0; (no_of_uris /=256) > 0; uri_byte_cut++);

  return true;
}

steg_config_t *
http_apache_steg_t::cfg()
{
  return config;
}

size_t
http_apache_steg_t::transmit_room(size_t pref, size_t lo, size_t hi)
{
  if (have_transmitted)
    /* can't send any more on this connection */
    return 0;

  if (config->is_clientside) {
    // MIN_COOKIE_SIZE and MAX_COOKIE_SIZE are *after* base64'ing
    if (lo < c_min_uri_length * 3/4)
      lo = c_min_uri_length *3/4;

    if (hi > c_max_uri_length*3/4)
      hi = c_max_uri_length*3/4;
    
    if (hi < lo)
      log_abort("hi<lo: client=%d type=%d hi=%ld lo=%ld",
                config->is_clientside, type,
                (unsigned long)hi, (unsigned long)lo);

    return clamp(pref + rng_range_geom(hi - lo, 8), lo, hi);

  }

  //Server side
  return http_steg_t::transmit_room(pref,  lo, hi);
}

int
http_apache_steg_t::transmit(struct evbuffer *source)
{
  if (config->is_clientside) {
      return http_client_uri_transmit(source, conn);
      //return http_client_cookie_transmit(source, conn);
  }
  else
    return http_steg_t::transmit(source);
}

int
http_apache_steg_t::receive(struct evbuffer *dest)
{
  return http_steg_t::receive(dest);
}
