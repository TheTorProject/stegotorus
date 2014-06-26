/*  2011, 2012, 201, 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef MODUS_OPERANDI_H
#define MODUS_OPERANDI_H

#include <string>
#include <stdint.h>
#include <vector>

#include "cpp.h"


using std::vector;
using std::string;

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

  //bool persist_mode(void){ return _persist_mode; }

  //string shared_secret(void){ return _shared_secret; }

  bool disable_encryption(void){ return _disable_encryption; }

  bool disable_retransmit(void){ return _disable_retransmit; }
  

  /* process options */
  bool daemon(void){ return _daemon; }

  bool logmethod_set(void){ return _logmethod_set; }

  string pid_file(void){ return _pid_file; }

  DISALLOW_COPY_AND_ASSIGN(modus_operandi_t);
 
 private: bool _is_ok;
  
  /* protocol options */
 private: string _protocol;
 private: string _mode;
 private: string _up_address;
 private: vector<string> _down_addresses;
  
  /* chop options */
 private: bool _trace_packets;
 //private: bool _persist_mode;
 //private: string _shared_secret;
 private: bool _disable_encryption;
 private: bool _disable_retransmit;
 
  /* process options */
 private: bool _daemon;
 private: bool _logmethod_set;
 private: string _pid_file;


  /* helper routines */
 private: bool process_line(string&, int32_t);

 private: string trim_line(string&);

 private: bool line_is(string&, const char *, string&);

 //private: bool set_scheme(const char *, string&, int32_t);
  
 private: bool set_bool(bool&, string&, int32_t);

};


#endif
