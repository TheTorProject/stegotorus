#ifndef _HTTP_H
#define _HTTP_H

#define MIN_COOKIE_SIZE 24
#define MAX_COOKIE_SIZE 1024

#define WAIT_BEFORE_TRANSMIT 100 //in milisecond a conn_t that receive should
                                    //wait before transmiting no matter what to 
                                    //keep the cover looks real

int
lookup_peer_name_from_ip(const char* p_ip, char* p_name);

  struct http_steg_config_t : steg_config_t
  {
    bool is_clientside : 1;
    //TODO: Make the payload server not a proper self destructing object not a pointer
    PayloadServer* payload_server;

    //list of user config for http steg
    user_config_dict_t http_steg_user_configs;
      
    //list of available steg type modules
    map<unsigned int, FileStegMod*> file_steg_mods;    

    /** If you are a child of http_steg_t and you want to initiate your own,
        you need to call this constructor in your config_t constructor instead.
        In normal world we could have http_trace_steg which only implements 
        few functions. But here because of these MODULE macros it forces us 
        to re-implement everthing. So I thought it's not worth it to have so
        much useless code just to change 2 lines.
    */
    http_steg_config_t(config_t *cfg, const std::vector<std::string>& options, bool init_payload_server);
    http_steg_config_t(config_t *cfg, const YAML::Node& options, bool init_payload_server);

    /* it is unfortunate that c++ isn't flexibale enough to allow calling a
       a constructor inside another and we have to have another init function
       called by both constructors */
    void init_http_steg_config_t(bool init_payload_server);
    
    /**
       reads the http_steg related option off the option list and store them in
       a map.

       @param options a list of strings contating the options

       @return true if the options are valid, otherwise false
     */
    bool store_options(const std::vector<string>& options);

    /**
       reads the http_steg related option off the option YAML node and store 
       them in a map.

       @param options a YAML Node which contains http steg conf options

       @return true if the options are valid, otherwise false
    */
    bool store_options(const YAML::Node& options);

    
    /**
       init the each file steg mod
    */
    void init_file_steg_mods();

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
    virtual int http_client_receive(evbuffer *source, evbuffer *dest);
  };

#endif
