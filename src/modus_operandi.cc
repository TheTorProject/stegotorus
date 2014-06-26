/* Copyright 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#include <sstream>
#include <fstream>

#include <stdint.h>
#include <errno.h>


#include "util.h"
#include "protocol.h"
#include "modus_operandi.h"
//#include "steg/schemes.h"

using std::ifstream;

/*
 * Perfect should not be the enemy of good.
 *
 */


down_address_t::down_address_t()
  : ok(false), ip(), steg()
{

}

void down_address_t::parse(string line) 
{
  size_t space = line.find_first_of(" \t");
  if(space == string::npos){
    return;
  } else {
    string front = line.substr(0, space);
    string back = line.substr(space);
    front = trim(front);
    back = trim(back);
    if(!front.empty() && !back.empty()){
      ip = front;
      steg = back;
      ok = true;
    }
  }
}

modus_operandi_t::modus_operandi_t()
  :  _is_ok(false),
     _protocol(), _mode(), _up_address(), _down_addresses(),
     _trace_packets(false), /*_persist_mode(false), _shared_secret(),*/ _disable_encryption(false), _disable_retransmit(false),
     _daemon(false), _logmethod_set(false), _pid_file() { }


bool modus_operandi_t::process_line(string &line, int32_t lineno){
  string rest;
  if(line_is(line, "protocol", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing protocol value on line %" PRId32"\n", lineno);
      return false;
    }
    else if(!config_is_supported(rest.c_str())){
      fprintf(stderr, "Protocol %s on line %" PRId32" is not supported!\n", rest.c_str(), lineno);
      return false;
    } else {
      this->_protocol = rest;
      return true;
    }
  }
  else if(line_is(line, "mode", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing mode value on line %" PRId32"\n", lineno);
      return false;
    }
    else if((rest == "server") || (rest == "socks") || (rest == "client")){
      this->_mode = rest;
      return true;
    } else {
      fprintf(stderr, "Mode %s on line %" PRId32" is not supported!\n", rest.c_str(), lineno);
      return false;
    }
  }
  else if(line_is(line, "up-address", rest)){
    rest = trim(rest);
    //ok need to ...
    if(rest.empty()){
      fprintf(stderr, "Missing up-address value on line %" PRId32"\n", lineno);
      return false;
    } else {
      this->_up_address = rest;
      return true;
    }
  }
  else if(line_is(line, "down-address", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing down-address value on line %" PRId32"\n", lineno);
      return false;
    } else {
      this->_down_addresses.push_back(rest);
      return true;
    }
  }
  else if(line_is(line, "log-min-severity", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing log-min-severity value on line %" PRId32"\n", lineno);
      return false;
    }
    else if((rest == "warn") || (rest == "info") || (rest == "debug")){
      if (log_set_min_severity(rest.c_str()) < 0) {
        fprintf(stderr, "invalid min. log severity '%s'", rest.c_str());
        return false;
      }
      return true;
    } else {
      fprintf(stderr, "Log-min-severity %s on line %" PRId32" is not supported!\n", rest.c_str(), lineno);
      return false;
    }
  }
  else if(line_is(line, "log-file", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing log-file value on line %" PRId32"\n", lineno);
      return false;
    }
    else if( log_set_method(LOG_METHOD_FILE, rest.c_str()) < 0) {
      fprintf(stderr, "failed to open logfile '%s': %s\n", rest.c_str(), strerror(errno));
      return false;
    } else {
      _logmethod_set = true;
    }
    return true;
  }
 /* else if(line_is(line, "shared-secret", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing shared-secret value on line %" PRId32"\n", lineno);
      return false;
    } else {
      this->_shared_secret = rest;
      return true;
    }
  }*/
  else if(line_is(line, "pid-file", rest)){
    rest = trim(rest);
    if(rest.empty()){
      fprintf(stderr, "Missing pid-file value on line %" PRId32"\n", lineno);
      return false;
    } else {
      this->_pid_file = rest;
      return true;
    }
  }
  /*else if(line_is(line, "cookie-transmit", rest)){
    return set_scheme("cookie-transmit", rest, lineno);
  }
  else if(line_is(line, "uri-transmit", rest)){
    return set_scheme("uri-transmit", rest, lineno);
  }
  else if(line_is(line, "json-post", rest)){
    return set_scheme("json-post", rest, lineno);
  }
  else if(line_is(line, "pdf-post", rest)){
    return set_scheme("pdf-post", rest, lineno);
  }
  else if(line_is(line, "jpeg-post", rest)){
    return set_scheme("jpeg-post", rest, lineno);
  }
  else if(line_is(line, "raw-post", rest)){
    return set_scheme("raw-post", rest, lineno);
  }
  else if(line_is(line, "swf-get", rest)){
    return set_scheme("swf-get", rest, lineno);
  }
  else if(line_is(line, "pdf-get", rest)){
    return set_scheme("pdf-get", rest, lineno);
  }
  else if(line_is(line, "js-get", rest)){
    return set_scheme("js-get", rest, lineno);
  }
  else if(line_is(line, "html-get", rest)){
    return set_scheme("html-get", rest, lineno);
  }
  else if(line_is(line, "json-get", rest)){
     return set_scheme("json-get", rest, lineno);
  }
  else if(line_is(line, "jpeg-get", rest)){
    return set_scheme("jpeg-get", rest, lineno);
  }
  else if(line_is(line, "raw-get", rest)){
    return set_scheme("raw-get", rest, lineno);
  }*/
  else if(line_is(line, "trace-packets", rest)){
    return set_bool(this->_trace_packets, rest, lineno);
  }
 /* else if(line_is(line, "persist-mode", rest)){
    return set_bool(this->_persist_mode, rest, lineno);
  }*/
  else if(line_is(line, "daemon", rest)){
    return set_bool(this->_daemon, rest, lineno);
  }
  else if(line_is(line, "disable-encryption", rest)){
    return set_bool(this->_disable_encryption, rest, lineno);
  }
  else if(line_is(line, "disable-retransmit", rest)){
    return set_bool(this->_disable_retransmit, rest, lineno);
  }

  fprintf(stderr, "Did not understand line[%" PRId32"] = %s\n", lineno, line.c_str());

  return false;
}


bool modus_operandi_t::line_is(string& line, const char *prefix, string& rest){
  size_t len =  strlen(prefix);
  if(!line.compare(0, len, prefix)){
    rest = line.substr(len);
    return true;    
  } else {
    return false;
  }
}

string modus_operandi_t::trim_line(string &line){
  string retval;
  size_t hash = line.find_first_of("#"); 
  if(hash == string::npos){
    retval = trim(line);
  } else if(hash == 0) {
    retval  = "";
  } else {
    retval = line.substr(0, hash);
    retval = trim(retval);
  }
  return retval;
}

bool modus_operandi_t::load_file(const char* path){
  string line;
  ifstream infile(path);
  int32_t lineno = 0;
  int32_t errors = 0;
  bool open_ok = infile.is_open();
  
  if(open_ok){
  
    while (getline(infile, line))
    {
      line = trim_line(line);
      if(!line.empty()  && (line[0] != '#')){
        bool line_ok = process_line(line, lineno);
        if(!line_ok){
          fprintf(stderr, "line[%" PRId32"]: had errors\n", lineno);
          errors++;
        }
      }
      lineno++;
    }

    //schemes_dump(stderr);
    
    if (errors == 0){
      /* the bare minimum for both chop and null */
      _is_ok = true;
    }
    infile.close();
  }

  if(!open_ok){
    fprintf(stderr, "Couldn't open file \"%s\"\n", path);
  } else if(!_is_ok){
    fprintf(stderr, "Loading file \"%s\" ... FAILED\n", path);
  } else {
    fprintf(stderr, "Loading file \"%s\" ... OK\n", path);
  }
  return _is_ok;
}

/*bool modus_operandi_t::set_scheme(const char *scheme_name, string& rest, int32_t lineno){
  int scheme = schemes_string_to_scheme(scheme_name);

  assert(scheme != -1);

  rest = trim(rest);
  if(!rest.empty()){
    int val = atoi(rest.c_str());
    return schemes_set_scheme(scheme , val);
  } else {
    fprintf(stderr, "Missing value %s on line %" PRId32"\n", scheme_name, lineno);
  }

  return false;
}*/

bool modus_operandi_t::set_bool(bool& boolref, string& rest, int32_t lineno){
  rest = trim(rest);
  if(!rest.empty()){
    int val = atoi(rest.c_str());
    if((val == 0) || (val == 1)){
      boolref = val;
      return true;
    }
  } else {
    fprintf(stderr, "Missing value on line %" PRId32"\n", lineno);
  }

  return false;



}
