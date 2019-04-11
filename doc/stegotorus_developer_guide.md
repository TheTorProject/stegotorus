# Stegotorus Developer Guide

## Overview

Stegotorus makes it easier for developers to write Pluggable Transports (PT), which seek to transform the shape of the traffic or conceal the traffic as another traffic. It does so by taking care of all networking complications and leaves only the encoding part to the PT. In Stegotorus jargon, the form-transforming pluggable transports are called Steg modules.

In the first section of this guide, we explain the needed steps for adding a new Steg module to Stegotorus. In the second section of this guide, we go into the details of the `http` Steg module, the current HTTP Pluggable Transport implemented in Stegotorus. We  explain how to apply a new encoding for other popular file formats transported using the HTTP protocol over the Internet.

## Writing a new Steg Module

In this section, we describe the needed steps for writing a new Steg module for the Chop protocol. In this tutorial, we assume that our new Steg module is called "scrample".

### Create the steg module implementation file 

You need to create a new .cc file in `/path/to/stegotorus/src/steg` which will contain the source code of the new Steg module. The name of the file should be the same as the name of the Steg module.

In our example we create:
   
    /path/to/stegotorus/src/steg/scrample.cc
    
### Include the necessary headers

Include in the follwing header files in the module implementation file:

    #include <vector>
    #include <event2/buffer.h>

    #include "connections.h"
    #include "protocol.h"
    #include "steg.h"

### Declare the configuration sturct

When Chop is informed about a Steg module associated with a downstream address at the startup time, it makes a configuration object from the configuration struct associated with that module. Configuration struct keeps the configurations for the Steg module which are persistent across different connections related to that Steg module.

You need to inherit MODULE_steg_config_t from `steg_config_t` and you need to apply `STEG_CONFIG_DECLARE_METHODS` macro to the Steg module name (this is an attempt of reimplementing inheritance in C which is the language Obfs proxy was written in and from which Stegotorus was forked off):

    namespace {
        struct scrample_steg_config_t : steg_config_t {
            STEG_CONFIG_DECLARE_METHODS(scrample);
        }
    }

Also note that it should be declared inside an anonymous namespace.
    
### Declare the Steg module struct 

When Chop is handed a new connection, it creates and associates a Steg module object to it which is responsible for encoding the data sent, and decodes the data received on the connection. This object handles the actual encoding for one connection and is responsible for tracking the per-connection state for the cover protocol if any.

Similar to the configuration struct, you need to inherit MODULE_steg_t from `steg_t` (also in an anonymous namespace), and you need to apply 
`STEG_DECLARE_METHODS` macro to the Steg module name in it.

    struct scrample_steg_t : steg_t
    {
        STEG_DECLARE_METHODS(nosteg);
    };

Additionally, you need to add a new member constructor which takes a pointer to the Steg module configuration object and a pointer to the connection which the Steg module is managing.

You also probably need to store these pointers for later use, so you need member variables for them:

    struct scrample_steg_t : steg_t
    {
        scrample_steg_config_t *config;
        conn_t *conn;

        scrample_steg_t(scrample_steg_config_t *cf, conn_t *cn);
        STEG_DECLARE_METHODS(nosteg);
    };

### Implement the configuration functions

You need to implement the `steg_create` function. It should create a `MODULE_steg_t` object which will manage the connection `conn` sent to this function.

    steg_t *steg_create(conn_t *conn)
    
### Implement the Steg module functions

Finally, you need to implement the functions which do the encoding and decoding on the connection data. 

* `steg_config_t *cfg()`

This function Should return the global configuration object associated with this Steg module.

* `size_t transmit_room(size_t pref, size_t min, size_t max)`

The chop is using this function to tell the Steg module that it would like to transmit PREF bytes on your  connection. Return an adjusted number of bytes; you may adjust down to indicate that you cannot transmit all of the available data, or up to indicate that it should be padded.

Returning zero indicates that your connection cannot transmit at all right now; if you do this, transmit() will not be called. Returning any nonzero value indicates that you want to transmit
exactly that number of bytes. The protocol may or may not call transmit() after you return a nonzero value, but if it does, it will provide the number of bytes you requested.

If you return a nonzero value, it MUST be greater than or equal to MIN, and less than or equal to MAX.  PREF is guaranteed to be in this range already. 

* `int transmit(struct evbuffer *source)`

It should encode all data in SOURCE,  write it to the outbound buffer of its connection; it returns 0 on success, -1 on failure.

* `int receive(struct evbuffer *dest)`

Decode as much of the data in your connection's inbound buffer as possible, and write it to DEST.  Return 0 on success, -1 on failure. If more data needs to come over, the wire before anything can be decoded, that is *not* a failure condition; return 0, but do not consume any data or write anything to DEST.

### Add the file to the STEGANOGRAPHERS list

Open `/path/to/stegotorus/src/steg/Makefile.am` and add the steg module file name to the STEGANOGRAPHERS list there:

    STEGANOGRAPHERS = \
	    src/steg/b64cookies.cc \
	    src/steg/cookies.cc \
	    src/steg/embed.cc \
	    src/steg/http.cc \
        ...
        src/steg/apache_payload_server.cc \
        src/steg/scrample.cc 

Re-run configure so that make can compile the new Steg module and link it to Stegotorus:

    ./configure
    make

Now you should be able to specify your new Steg module in the command line or in your config file to be used by Chop.
    
## Writing an encoder/decoder for new file format for http Steg module

http Steg module encodes data into popular files transmitted using HTTP protocol while preserving their original format as much as possible. As such, for each file
format it needs a specific encoder which understands the file format and replaces parts of the current content of the file with user data without 
destroying the file format in a distinct way.

In this section, we describe how to write an encoder/decoder for a new file format. In this tutorial, we assume that we are writing an encoder/decoder for extension `ext`. 

## Inheriting from FileStegMod

You need to create `extSteg.h` and `extSteg.cc` in the `http_steg_mods` folder:

    /path/to/stegotorus/src/steg/http_steg_mods/extSteg.h
    /path/to/stegotorus/src/steg/http_steg_mods/extSteg.cc

In the header file of your encoder you need to inherit from `FileStegMod` class:

    class EXTSteg : public FileStegMod {
    
## Implement the abstract functions

You need to implement the following abstract functions:

    /** 
    embeds the data in the cover buffer; the assumption is that the function does not expand the buffer size

     @param data: the data to be embeded
     @param data_len: the length of the data
     @param cover_payload: the cover in which the data will be embedded
     @param cover_len: cover size in bytes

     @return < 0 in case of error or length of the cover with embedded data at success
    
    */ 
    
    virtual int encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len) = 0;

    /**
    Embeds the data in the cover buffer, needs to be implemented by the different Steg modules. The steg_modules should make sure that the data is not larger than _MAX_MSG_BUF_SIZE

     @param data: the pointer to the buffer that is going to contain the data
     @param cover_payload: the cover in which the data will be embeded
     @param cover_len: cover size in bytes

     @return the length of recovered data or < 0 in case of error
    */
    
    virtual ssize_t decode(const uint8_t *cover_payload, size_t cover_len, uint8_t* data) = 0;
  
    /**
    Returns the capacity which can be encoded in the buffer assuming that the buffer starts with the  HTTP response header
    */
    
    virtual ssize_t capacity(const uint8_t* buffer, size_t len) = 0;

    /**
    Returns the capacity which can be encoded in the cover_body when cover_body does not include the HTTP response header 
     */
    
    virtual ssize_t headless_capacity(char *cover_body, int body_length) = 0;

### Inform the payload_server about the new format

Define a constant corresponding to the new format at the top of

    /path/to/stegotorus/src/steg/payload_server.h
    
    ...
    #define HTTP_CONTENT_PNG                7
    #define HTTP_CONTENT_GIF                8
    #define HTTP_CONTENT_EXT                9
    
Increase the `c_no_of_steg_protocol` constant defined in the same file.

Accordingly Update PayloadServer::extension_to_content_type function to 
know about the new type:

    int 
    PayloadServer::extension_to_content_type(const char* extension) {
        ...
        if (!strncmp(extension, "gif", 4) || !strncmp(extension, "GIF", 4))
            return HTTP_CONTENT_GIF;

        if (!strncmp(extension, "ext", 4) || !strncmp(extension, "ext", 4))
            return HTTP_CONTENT_EXT;
        
        return -1;
    }

### Inform the PayloadScraper about the new format

Update the `PayloadScraper` constructor in
    /path/to/stegotorus/src/steg/payload_scraper.cc
    
by adding a line for the new format at the end of the function:


    ...
    _available_stegs[7].type = HTTP_CONTENT_GIF; _available_stegs[7].extension = ".gif"; _available_stegs[7].capacity_function = GIFSteg::static_capacity;

    _available_stegs[8].type = HTTP_CONTENT_EXT; _available_stegs[8].extension = ".ext"; _available_stegs[8].capacity_function = EXTSteg::static_capacity; 

    _available_stegs[8+1].type = 0;

### Inform http steg module about the new format

Finally, inform http Steg module about the new format in:

    /path/to/stegotorus/src/steg/http.cc
    
add an entry to the function `init_file_steg_mods`:

    http_steg_config_t::init_file_steg_mods() {
        ...
        
        file_steg_mods[HTTP_CONTENT_GIF] = new GIFSteg(payload_server, noise2signal);
        file_steg_mods[HTTP_CONTENT_EXT] = new EXTSteg(payload_server, noise2signal);

        ...
    }
    
And by that, you have added a new file format as an HTTP cover.
