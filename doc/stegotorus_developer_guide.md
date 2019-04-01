# Stegotorus Developer Guide

## Overview

Stegotorus is makes it easier for developers to write Pluggable Transport which
seeks to transform the shape for the traffic or conceal the traffic as another 
traffic, by taking care of all networking complication and leave only the 
encoding part to the PT.

In Stegotorus jorgon, Form transforming Pluggable Transports are called Steg 
modules.

In the first part of this  guide we explain the steps needed to add a new Steg 
module 
to Stegotorus.

In the second part of this document we go into the details of `http` Steg
module, the current HTTP Pluggable Transport implemented in Stegotorus. We 
explain how to implement a new encoding for other popular file format 
transported using HTTP protocol the Internet.

## Writing a new Steg Module

In this section we describe the steps that are needed to write a new steg
module for the Chop protocol.

In this tutorial we assume that our new steg module is called "scrample".

### Create the steg module implementation file 
You need to create a new .cc file in `/path/to/stegotorus/src/steg` which will
contain the source code of the the new steg module. 

The name of the file should be the same as the name of the steg module.

So in our example we create:
   
    /path/to/stegotorus/src/steg/scrample.cc
    
### Include the necessary headers
You need to have following includes in the module implementation file

    #include <vector>
    #include <event2/buffer.h>

    #include "connections.h"
    #include "protocol.h"
    #include "steg.h"

### Declare the configuration sturct
When Chop is told about a Steg module associated with a downstream address 
at the start up time, it makes a configuration object from the configuration 
struct associated with that module. Configuration struct keeps the 
configurations for the steg module which are persistant across different
connections associated to that steg module.

You need to inheret MODULE_steg_config_t from `steg_config_t` and you need to 
apply `STEG_CONFIG_DECLARE_METHODS` macro to the Steg module name (this is a 
an attempt of re-implementing inheritance in c which is the language Obfs proxy 
was written in and Stegotorus was forked off of it):

    namespace {
        struct scrample_steg_config_t : steg_config_t {
            STEG_CONFIG_DECLARE_METHODS(scrample);
        }
    }

Also note that it should be declared inside an anonymous namespace.
    
### Declare the steg module struct 
When Chop is handed a new connection, it create and assocate an Steg module 
object to it which is responsible to encode the data sent and decode the data 
received on the connection. This object handles the actual encoding for one
connection, and is responsible for tracking per-connection state for the 
cover protocol, if any.

Similar the configuration struct, you need to inheret MODULE_steg_t from
`steg_t` (also in an anonymous namespace) and you need to apply 
`STEG_DECLARE_METHODS` macro to the Steg module name in it.

    struct scrample_steg_t : steg_t
    {
        STEG_DECLARE_METHODS(nosteg);
    };

Additionally you need to add a new member constractor which takes
a pointer the steg module configuration object and a pointer to 
the connection the steg module mananging.

You also probably need to store these pointer for later use
so you need member variables for them:

    struct scrample_steg_t : steg_t
    {
        scrample_steg_config_t *config;
        conn_t *conn;

        scrample_steg_t(scrample_steg_config_t *cf, conn_t *cn);
        STEG_DECLARE_METHODS(nosteg);
    };


### Implement the configuration functions

You need to implement `steg_create` function. It should create a `MODULE_steg_t` object 
which will manage the connection `conn` sent to this function.

    steg_t *steg_create(conn_t *conn)
    
### Implement the steg module functions
Finally you need to implement the functions which do the encoding and decoding on the
connection data. 

* `steg_config_t *cfg()`
should returns the global configuration object associated with this steg module.

* `size_t transmit_room(size_t pref, size_t min, size_t max)`

The chop using this to tell the steg module that it would like to transmit PREF
bytes on your connection.  Return an adjusted number of bytes; you may adjust down to indicate that you cannot transmit all of the available data, or up to indicate that it should be padded.

Returning zero indicates that your connection cannot transmit at
all right now; if you do this, transmit() will not be called.
Returning any nonzero value indicates that you want to transmit
exactly that number of bytes.  The protocol may or may not call
transmit() after you return a nonzero value, but if it does, it
will provide the number of bytes you requested.

If you return a nonzero value, it MUST be greater than or equal
to MIN, and less than or equal to MAX.  PREF is guaranteed to be
in this range already.

* `int transmit(struct evbuffer *source)`
It should encode all data in SOURCE,  write it to the outbound buffer 
of its connection, it returns 0 on success, -1 on failure.

* `int receive(struct evbuffer *dest)`
Decode as much of the data in your connection's inbound buffer
as possible, and write it to DEST.  Return 0 on success, -1 on
failure.  If more data needs to come over the wire before
anything can be decode, that is *not* a failure condition;
return 0, but do not consume any data or write anything to DEST.

### Add the file to the STEGANOGRAPHERS list
Open `/path/to/stegotorus/src/steg/Makefile.am` and add the steg module
file name to the STEGANOGRAPHERS list there:

    STEGANOGRAPHERS = \
	    src/steg/b64cookies.cc \
	    src/steg/cookies.cc \
	    src/steg/embed.cc \
	    src/steg/http.cc \
        ...
        src/steg/apache_payload_server.cc \
        src/steg/scrample.cc 

Re-run configure so make can compile the new steg module and link it 
to Stegotorus:

    ./configure
    make

Now you should be able to specify your new steg module in the commandline
or in your config file to be use by Chop.
    
## Writing an encoder/decoder for new file forma for http steg module

Uses encodes datas into popular files transmitted using HTTP protocol while 
preserving their original format as much as possible. As such, for each file
format, it needs a specific encoder which understands the file format and 
replace part of the current content of the file with user data without 
destorying the file format in a distinguishable way.

In this section, we describe how to write an encoder/decoder for a new file
format. In this tutorial we assume that we are writing an encoder/decoder for 
extension `ext`. 

## Inheriting from FileStegMod
You need to create `extSteg.h` and `extSteg.cc` in the `http_steg_mods` folder:

    /path/to/stegotorus/src/steg/http_steg_mods/extSteg.h
    /path/to/stegotorus/src/steg/http_steg_mods/extSteg.cc

In the header file of your encoder  you need to inheret from `FileStegMod` 
class:

    class EXTSteg : public FileStegMod {
    
## Implement the abstract functions

You need to implement the following abstract functions:

  /**
     embed the data in the cover buffer, the assumption is that
     the function doesn't expand the buffer size

     @param data: the data to be embeded
     @param data_len: the length of the data
     @param cover_payload: the cover to embed the data into
     @param cover_len: cover size in byte

     @return < 0 in case of error or length of the cover with embedded dat at success
   */
  virtual int encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len) = 0;

  /**
     Embed the data in the cover buffer, need to be implemented by the
     different steg modules. The steg_modules should make sure that
     that the data is not larger than _MAX_MSG_BUF_SIZE

     @param data: the pointer to the buffer that is going to contain the
            data
     @param cover_payload: the cover to embed the data into
     @param cover_len: cover size in byte

     @return the length of recovered data or < 0 in case of error
   */
  virtual ssize_t decode(const uint8_t *cover_payload, size_t cover_len, uint8_t* data) = 0;
  
    /**
     Returns the capacity which can be encoded in the buffer
     assuming that the buffer starts with the  HTTP response header
  */
  virtual ssize_t capacity(const uint8_t* buffer, size_t len) = 0;

  /**
     Returns the capacity which can be encoded in the cover_body
     when cover_body does not include the HTTP response header */
   virtual ssize_t headless_capacity(char *cover_body, int body_length) = 0;


### Inform the payload_server about the new format
Define a constant corresponding to the new format at the top of

    /path/to/stegotorus/src/steg/payload_server.h
    
    ...
    #define HTTP_CONTENT_PNG                7
    #define HTTP_CONTENT_GIF                8
    #define HTTP_CONTENT_EXT                9
    
Increase the `c_no_of_steg_protocol` constant defined in the same file.

Accordingly Update PayloadServer::extension_to_content_type function no 
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
Finall inform http steg module about the new format in:

    /path/to/stegotorus/src/steg/http.cc
    
add an entry to the function `init_file_steg_mods`:

    http_steg_config_t::init_file_steg_mods() {
        ...
        
        file_steg_mods[HTTP_CONTENT_GIF] = new GIFSteg(payload_server, noise2signal);
        file_steg_mods[HTTP_CONTENT_EXT] = new EXTSteg(payload_server, noise2signal);

        ...
    }
    
And by that you have added new file format as an http cover.

