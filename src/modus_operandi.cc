/* Copyright 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#include <sstream>
#include <fstream>

#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <yaml-cpp/yaml.h>

#include <getopt.h>
#include <cstdint>

#include "util.h"
#include "protocol.h"
#include "modus_operandi.h"
//#include "steg/schemes.h"
//#include "steg/jel_knobs.h"
//#include "steg/http.h"
//#include "steg/jpegSteg.h"

using std::ifstream;

/*
 * Perfect should not be the enemy of good.
 *
 */

const struct option modus_operandi_t::long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "config-file", required_argument, NULL, 'c' },
    { "log-file", required_argument, NULL, 'l' },
    { "log-min-severity", required_argument, NULL, 's' },
    { "no-log", no_argument,NULL, 'n' },
    { "timestamp-logs", no_argument, NULL, 't' },
    { "allow-kqueue", no_argument, NULL, 'k' },
    { "registration-helper", required_argument, NULL, 'r' },
    { "pid-file", required_argument, NULL, 'p' },
    { "daemon", no_argument, NULL, 'd' },
    { NULL, 0, NULL, 0 }
  };

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

/**
 * validate the config by checking for unknown keyword at
 * stegotorus level (protocol are responsible to check for
 * validity of the config*/
bool modus_operandi_t::validate_top_level_config(const YAML::Node& conf_node) {
  for(auto cur_conf_option : conf_node)
    if (!(std::find(config_valid_extra_key_words.begin(), config_valid_extra_key_words.end(), cur_conf_option.first.as<std::string>()) != config_valid_extra_key_words.end()) &&
        find_long_option(cur_conf_option.first.as<std::string>()) == -1)
      return false;

  return true;
}


modus_operandi_t::modus_operandi_t()
{
}

/**
 * processes the command line argument based on the place they 
 * have been mentioned they might over write config file options
 * 
 * @param argv the array containing command line arguments 
 * @param argc number of elements in argv
 *
 * @return the index of where the protocol options start
 *
 */
int
modus_operandi_t::process_command_line_config(char* const*argv,  const int argc)
{
    //Dealing with command line option
    int next_option;

    //first we detect where the protocol section start to feed
    //what comes before to getopts
    int protocol_spec_index = 1;
    for(; argv[protocol_spec_index] && !strncmp(argv[protocol_spec_index],"--",2); protocol_spec_index++);

    do {
      next_option = getopt_long (argc, argv, short_options, long_options, NULL);
      bool unknown_option = true;
        
      switch (next_option)
        {
        case 'h':
          /* -h or --help */
          /* User has requested usage information. Print it to standard
             output, and exit with exit code zero (normal termination). */
          usage();
        case '?':
          /* The user specified an invalid option. */
          /* Print usage information to standard error, and exit with exit
             code one (indicating abnormal termination). */
          usage();
        case -1:
          break;
          /* Done with options.
           */
        default:
          for(auto cur_option = long_options; cur_option->name != nullptr; cur_option++)
            if (next_option == cur_option->val) {
              //prevent double options
              if (top_level_confs_dict.find(cur_option->name) != top_level_confs_dict.end())
                  log_abort("option %s has already been specified", cur_option->name);
                  
              if (cur_option->has_arg == required_argument) {
                top_level_confs_dict[cur_option->name] = optarg;
              } else if (cur_option->has_arg == no_argument) {
                top_level_confs_dict[cur_option->name]  = true_string;
              }
              unknown_option = false;
              break;
                
            }

          if (unknown_option) {
            /* Something else: unexpected.*/
            log_abort("error in processing command line arguments");
             abort ();
            
          }
        }
    }
    while (next_option != -1);

    return protocol_spec_index;
}

/**
 * loads the config file in YAML format and store the 
 * values in the *this* object in heirercal format. It does not
 * validate the values.
 */

void
modus_operandi_t::load_file(const string& path){
    // Read the file. If there is an error, report it and exit.
  log_debug("Reading configuration from [%s]", path.c_str());

  try
  {
     const YAML::Node& cfg = YAML::LoadFile(path);

    //we make sure there is no unknow keyboard 
    if (!validate_top_level_config(cfg)) {
      usage();
      log_abort("unknown option");
    }

    //otherwise all we do is to delegate reading the protocol
    //config to process_protocol and store other config in
    //a string->string dict
    for (YAML::const_iterator it=cfg.begin();it!=cfg.end();++it) {
      std::string node_name = (*it).first.as<std::string>();
      string rest;
      if(node_name == "protocols") {
        protocol_configs = it;
      } else {
        int option_index = find_long_option(node_name);
        if (option_index == -1) //this shouldn't happen as we have checked validity before
          log_abort("something went wrong. A wrong option sneaked in");
        
        if (long_options[option_index].has_arg == no_argument) //uniformized the boolean config
          top_level_confs_dict[node_name] = uniformize_boolean_value((*it).second.as<std::string>());
        else //otherwise just store the original
          top_level_confs_dict[node_name] = (*it).second.as<std::string>();
      }
    }
  }  catch(YAML::BadFile& e) {
    log_abort( "I/O error while reading config file [%s]: [%s]. Make sure that file exists.", path.c_str(), e.what());
  }
  catch(YAML::ParserException& e) {
    log_abort("parsing error while reading config file [%s]: [%s].", path.c_str(), e.what());
  } catch( YAML::RepresentationException &e ) {
    log_abort("bad config format %s", e.what());
  }
      
  log_info("finished loading conf");
}

/**
   Prints usage instructions then exits.
*/
void ATTR_NORETURN
modus_operandi_t::usage(void)
{
    const proto_module *const *p;
    
    fputs("usage: stegotorus protocol_name [protocol_args] protocol_options "
          "protocol_name ...\n"
          "* Available protocols:\n", stderr);
    /* this is awful. */
    for (p = supported_protos; *p; p++)
      fprintf(stderr,"[%s] ", (*p)->name);
    fprintf(stderr, "\n* Available arguments:\n"
	  "--config-file=<file> ~ load the configuration file\n"
          "--log-file=<file> ~ set logfile\n"
          "--log-min-severity=warn|info|debug ~ set minimum logging severity\n"
          "--no-log ~ disable logging\n"
          "--timestamp-logs ~ add timestamps to all log messages\n"
          "--allow-kqueue ~ allow use of kqueue(2) (may be buggy)\n"
          "--registration-helper=<helper> ~ use <helper> to register with "
          "a relay database\n"
          "--pid-file=<file> ~ write process ID to <file> after startup\n"
          "--daemon ~ run as a daemon\n"
          "--version ~ show version details and exit\n");

    exit(1);
}
