/*  2011, 2012, 201, 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef MODUS_OPERANDI_H
#define MODUS_OPERANDI_H

#include <string>
#include <stdint.h>
#include <vector>
#include <algorithm>

#include <getopt.h>

#include <yaml-cpp/yaml.h>

#include "cpp.h"
//#include "steg/jel_knobs.h"

using std::vector;
using std::string;

enum class StegData { TRACES, IMAGES, PDFS, STREAM };

#define STEG_TRACES_DIR "./traces"

/* for parsing in chop.cc */
class down_address_t {
  
 public: down_address_t(void);

 public: void parse(string);

 public: bool ok;

 public: string ip;

 public: string steg;

};

/**
 * read, validate and update the config structure.
 */
class modus_operandi_t {
 protected:
  /* A string listing valid short options letters.*/
  const char* const short_options = "hc:l:s:ntkr:p:d";
  const std::vector<std::string> config_valid_extra_key_words = {"protocols"};
  /* An array describing valid long options. */
  static const struct option long_options[];

  /**
   * spots line curresponding to the long option in the getopts 
   * option list.
   *
   * @param the option keyword to search for
   *
   * @return the index of the option in the array or -1 
   *         if not found
   */
  int find_long_option(const string& long_option_name) {
    for(int i = 0; long_options[i].name != nullptr; i++)
      if (long_option_name == long_options[i].name)
        return i;
  
    return -1;
 
  }

  /**
   * validate the config by checking for unknown keyword at
   * stegotorus level (protocol are responsible to check for
   * validity of the config*/
  bool validate_top_level_config(const YAML::Node& conf_node);

    /**
   * read the hierechical struture of the protocol from the YAML configs
   * and store them in the protocols_config_dict. abort if config has
   * problem.
   *
   * @param protocols_node the YAML node which points to protocols:
   *        node in the config file
   */
  void process_protocols(const YAML::Node& protocols_node);

  /**
   * read the hierechical struture of the protocol from the commandline
   * args store them in the protocols_config_dict. abort if config has
   * problem.
   */
  void process_protocol(const char* argv);

 public:
  //TODO: these needs access function
  YAML::Node protocol_configs;
  //This is basically to track if user has specified any protocol
  size_t number_of_protocols = 0;
  config_dict_t top_level_confs_dict;

  modus_operandi_t();

  /**
   * reads the file using yaml module, validate it and store the
   * config values in hierarchical dicts.
   */ 
  void load_file(const string& path);

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
  int process_command_line_config(const char *const *argv,  const int argc);

  /**
   * helper functions which uniformizes the value of boolean config to
   * one string represetation.
   * 
   * @param stringized_boolean_value a string which represent a boolean 
   *        value. 0, False, FALSE, false represents false. 1, True, TRUE
   *        true represent true.
   *
   *
   * @return "false" or "true" for valid values or "" for invalid value.
   **/
  static std::string uniformize_boolean_value(const std::string& stringized_boolean_value)
  {
    static const std::vector<std::string> false_representations = {"0", "False", "FALSE", "false"};   

    static const std::vector<std::string> true_representations = {"1", "True", "TRUE", "true", ""};
    if (std::find(false_representations.begin(),false_representations.end(),stringized_boolean_value) !=  false_representations.end())
      return false_string;
    else if (std::find(true_representations.begin(),true_representations.end(),stringized_boolean_value) !=  true_representations.end())
      return true_string;
    else
      return "";

  }

   /**
   * a helper function to check if a specific config
   * keyboard exists in the config dictionary
   *
   * @param keyword_option the keyword specifying the option
   *
   * @return true if the option is exists in the config dictionary otherwise returns
   *         false.
   */
  bool is_set(std::string keyword_option)
  {
    return (top_level_confs_dict.find(keyword_option) != top_level_confs_dict.end());
  }

  /**
   Prints usage instructions then exits.
  */
  static void ATTR_NORETURN
    usage(void);

};


#endif
