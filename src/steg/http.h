#ifndef _HTTP_H
#define _HTTP_H

#define MIN_COOKIE_SIZE 24
#define MAX_COOKIE_SIZE 1024

int
lookup_peer_name_from_ip(const char* p_ip, char* p_name);

  struct http_steg_config_t : steg_config_t
  {
    bool is_clientside : 1;
    PayloadServer* payload_server;

    /** If you are a child of http_steg_t and you want to initiate your own,
        you need to call this constructor in your config_t constructor instead.
        In normal world we could have http_trace_steg which only implements 
        few functions. But here because of these MODULE macros it forces us 
        to re-implement everthing. So I thought it's not worth it to have so
        much useless code just to change 2 lines.
    */
    http_steg_config_t(config_t *cfg, bool init_payload_server);

    STEG_CONFIG_DECLARE_METHODS(http);

  };

  struct http_steg_t : steg_t
  {
    http_steg_config_t *config;
    conn_t *conn;
    char peer_dnsname[512];

    bool have_transmitted : 1;
    bool have_received : 1;
    int type;

    http_steg_t(http_steg_config_t *cf, conn_t *cn);
    STEG_DECLARE_METHODS(http);

    size_t clamp(size_t val, size_t lo, size_t hi);
    virtual int http_client_uri_transmit (struct evbuffer *source, conn_t *conn);
    virtual int http_client_cookie_transmit (struct evbuffer *source, conn_t *conn);
    virtual int http_server_receive(conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

  };

#endif
