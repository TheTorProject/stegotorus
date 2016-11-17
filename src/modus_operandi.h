/*  2011, 2012, 201, 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef MODUS_OPERANDI_H
#define MODUS_OPERANDI_H

#include <string>
#include <stdint.h>
#include <vector>

#include "cpp.h"
#include "steg/jel_knobs.h"


using std::vector;
using std::string;

enum class StegData { TRACES, IMAGES, PDFS, STREAM };


/* for parsing in chop.cc */
class down_address_t {
  
 public: down_address_t(void);

 public: void parse(string);

 public: bool ok;

 public: string ip;

 public: string steg;

};


class modus_operandi_t {


 public:
  
  modus_operandi_t();

  bool load_file(const char* path);

  bool is_ok(void){ return  _is_ok; }

  /* protocol options */
  string protocol(void){  return _protocol; }

  string mode(void){  return _mode; }

  string up_address(void){  return _up_address; }

  vector<string> down_addresses(){ return _down_addresses; }

  /* chop options */
  bool trace_packets(void){ return _trace_packets; }

  bool persist_mode(void){ return _persist_mode; }

  string shared_secret(void){ return _shared_secret; }

  bool disable_encryption(void){ return _disable_encryption; }

  bool disable_retransmit(void){ return _disable_retransmit; }
  

  /* process options */
  bool managed(void){ return _managed; }
  void managed(bool val){  _managed = val; }

  string managed_method(void){ return _managed_method; }

  bool daemon(void){ return _daemon; }

  bool logmethod_set(void){ return _logmethod_set; }

  string pid_file(void){ return _pid_file; }

  /* steganographic options */
  string hostname(void){ return _hostname; }

  bool post_reflection(void){ return _post_reflection; }

  jel_knobs_t* jel_knobs(void){ return  &_jel_knobs; }
  
  /* steg data paths */

  string get_steg_datadir(StegData variety);
  bool set_steg_datadir(StegData variety, string value);
  
  DISALLOW_COPY_AND_ASSIGN(modus_operandi_t);
 
 private: bool _is_ok;
  
  /* protocol options */
 private: string _protocol;
 private: string _mode;
 private: string _up_address;
 private: vector<string> _down_addresses;
  
  /* chop options */
 private: bool _trace_packets;
 private: bool _persist_mode;
 private: string _shared_secret;
 private: bool _disable_encryption;
 private: bool _disable_retransmit;
 
  /* process options */
 private: bool _managed;
 private: string _managed_method;
 private: bool _daemon;
 private: bool _logmethod_set;
 private: string _pid_file;


  /* steganographic options */
 private: bool _post_reflection;
 private: string _hostname;
  

 private: jel_knobs_t _jel_knobs;

 private: string _traces_dir;
 private: string _images_dir;
 private: string _pdfs_dir;
 private: string _stream_dir;

  


  /* helper routines */
 private: bool process_line(string&, int32_t);

 private: string trim_line(string&);

 private: bool line_is(string&, const char *, string&);

 private: bool set_scheme(const char *, string&, int32_t);

 private: bool set_string(string&, const char *, string&, int32_t);
  
 private: bool set_bool(bool&, string&, int32_t);

 private: bool set_int(int&, string&, int32_t);

};


#endif
