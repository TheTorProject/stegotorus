#ifndef _HTTP_H
#define _HTTP_H

#define MIN_COOKIE_SIZE 24
#define MAX_COOKIE_SIZE 1024

int
http_server_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, struct evbuffer* source);

int
lookup_peer_name_from_ip(const char* p_ip, char* p_name);

  struct http_steg_config_t : steg_config_t
  {
    bool is_clientside : 1;
    PayloadServer* payload_server;

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
