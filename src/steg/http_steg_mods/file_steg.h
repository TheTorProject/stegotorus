#ifndef FILE_STEG_H
#define FILE_STEG_H

#define SWF_SAVE_HEADER_LEN 1500
#define SWF_SAVE_FOOTER_LEN 1500

#include <list>
#include <math.h>

using namespace std;

extern const unsigned int c_no_of_steg_protocol;

/**
   This is an abstract class that all steg modules should inherit from,
   and implemenet its virtual function so http steg module can use them
   to embed into the inherited file type
*/
class FileStegMod
{
protected:
  /**
     Constants
  */
  //Constants
  const int RESPONSE_GOOD = 0 ;
  const int RESPONSE_INCOMPLETE = -1;
  const int RESPONSE_BAD = -2;

  PayloadServer* _payload_server;
  double noise2signal; //making sure that the cover is bigger enough than the 
                       //the data to protect against statistical analysis
  const int c_content_type; //The inheriting class will set the type

  uint8_t* outbuf; //this is where the payload sit after being injected by the
  //the message. it is define as class member to avoid allocation and delocation

  //const int pgenflag; //tells us whether we are dealing with a payload taken from the database (0) or a generated on the fly one (1, for SWF only atm) 
  //not clear if we need this at all

  /**
     Finds a payload of approperiate type and size

     @param data_len: the payload should be able to accomodate this length
     @param payload_buf: the evbuffer that is going to contain the chosen payload

     @return payload size or < 0 in case of error
  */
  ssize_t pick_appropriate_cover_payload(size_t data_len, char** payload_buf, string& cover_id_hash);
  

  /**
     Encapsulate the repetative task of checking for the respones of content_type
     choosing one with appropriate size and extracting the body from header

     @param data_len: the length of data being embed should be < capacity
     @param payload_buf: the http response (header+body) corresponding going to cover the data
     @param payload_size: the size of the payload_buf

     @return the offset of the body content of payload_buf or < 0 in case of
             error, that is RESPONSE_INCOMPLETE (<0) if it is incomplete (can't
             find the start of body) or RESPONSE_BAD (<0) in case of other
             errors
  */
  static ssize_t extract_appropriate_respones_body(char* payload_buf, size_t payload_size);

  /**
     The overloaded version with evbuffer
  */
  ssize_t 
  extract_appropriate_respones_body(evbuffer* payload_buf);

  /**
     changes the size of Content Length in HTTTP response header, in case
     the steg module changes  the size of the coverafter emebedding data
   */
  size_t alter_length_in_response_header(uint8_t* original_header, size_t original_header_length, ssize_t new_content_length, uint8_t new_header[]);

 public:
  static const size_t c_HTTP_PAYLOAD_BUF_SIZE = HTTP_PAYLOAD_BUF_SIZE; //TODO: one constant //maximum
  //size of buffer which stores the whole http response
  static const  size_t c_MAX_MSG_BUF_SIZE = 131103; //max size of the message to be embeded
  //static const  size_t c_NO_BYTES_TO_STORE_MSG_SIZE = (static_cast<int>((log2(c_MAX_MSG_BUF_SIZE) + 31) / 32)) * 4; //no of bytes needed to store the message size rounded up to 4 bytes chunks
                                                       // no of bits in multiple of 32: n = [log2(c_MAX_MSG_BUF_SIZE) + 31) / 32]*32 =>
                                                       // no of bytes = n / 8
  //or it is just simpler to limit ourselves to 4G per message
  typedef uint32_t message_size_t;
  static const  size_t c_NO_BYTES_TO_STORE_MSG_SIZE = sizeof(message_size_t);
  static const size_t c_HIGH_BYTES_DISCARDER; //pow(2, c_NO_BYTES_TO_STORE_MSG_SIZE * 8);

  /** 
   * indicates if the steg mod is cover length preserving which is true 
   * by default. needs to be overrriden for unit testing of the steg modules
   *
   * @return true if the steg module doesn't change the length of cover
   *         after inserting the data, false otherwise
   */
  virtual bool cover_lenght_preserving() { return true; };

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
  
  const list<string> extensions;

  /**
     Returns the capacity which can be encoded in the buffer
     assuming that the buffer starts with the  HTTP response header
  */
  virtual ssize_t capacity(const uint8_t* buffer, size_t len) = 0;

  /**
     Returns the capacity which can be encoded in the cover_body
     when cover_body does not include the HTTP response header */
   virtual ssize_t headless_capacity(char *cover_body, int body_length) = 0;

  /**
     Find appropriate payload calls virtual embed to embed it appropriate
     to its typex
     @param source the data to be transmitted
     @param conn the connection over which the data is going to be transmitted

     @return the actual number of bytes (cover size) transmitted
  */
  virtual int http_server_transmit(evbuffer *source, conn_t *conn);

  /**
     Tries to extract the embeded data in source buffer and put them
     in dest. It returns INCOMPLETE or BAD if it fails

     @param source the received buffer over http conncetion
     @param dest will contain the extracted data from
            http cover

     @return RECV_GOOD if the extraction is successful, RECV_INCOMPLETE
             In case it can't find all the data in the cover (body etc)
             or bad.
  */
  virtual int http_client_receive(conn_t *conn, evbuffer *dest, 
                                  evbuffer *source);
  /**
     constructor, sets the playoad server

     @param the payload server that is going to be used to provide cover
            to this module.
     @child_type?
  */
  FileStegMod(PayloadServer* payload_provider, double noise2signal, int child_type);
  /** 
      Destructor, just releases the http buffer 
  */
  virtual ~FileStegMod();


  
};

#endif //FILE_STEG_H
