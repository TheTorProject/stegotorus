#ifndef CHOP_CONFIG_H
#define CHOP_CONFIG_H

#include <unordered_map>
#include <vector>

#include "crypt.h"
#include "transparent_proxy.h"

using std::unordered_map;

namespace chop_protocol {
struct chop_circuit_t;

typedef unordered_map<uint32_t, chop_circuit_t *> chop_circuit_table;

struct chop_config_t : config_t
{
  //we store protocol config to be able to treat them uniformly independant of
  //the fact that they came from command line or from yaml config file
  const std::vector<std::string> arg_option_list = {"name", "mode", "up-address", "server-key",
                                                    "passphrase", "cover-server",
                                                    "minimum-noise-to-signal"};

  const std::vector<std::string> binary_option_list = {"trace-packets",
                                                       "disable-encryption",
                                                       "disable-retransmit",
                                                       "enable-retransmit"};

  config_dict_t chop_user_config;
  std::list<config_dict_t> steg_user_conf_list;

  struct evutil_addrinfo *up_address;
  std::vector<struct evutil_addrinfo *> down_addresses;
  std::vector<steg_config_t *> steg_targets;
  chop_circuit_table circuits;
  bool trace_packets;
  bool trace_packet_data;
  bool encryption;
  bool retransmit;

    /* Performance calculators */
  unsigned long total_transmited_data_bytes;
  unsigned long total_transmited_cover_bytes;

  /*ecb encryptor and decryptor for the handshake*/
  ecb_encryptor* handshake_encryptor;
  ecb_decryptor* handshake_decryptor;

  /**
   * using the protocol dictionary provides a uniform init which can 
   * be called by both init functions which has populated the config
   * dict
   */
  bool init_from_protocol_config_dict();
  
  /**
     create the approperiate block cipher with 
     approperiate keys for the handshake
   */
  void init_handshake_encryption();
  /* Transparent proxy and cover server */
  std::string cover_server_address; //is the server that is going to serve covers
  TransparentProxy* transparent_proxy;

  double noise2signal; //to protect against statistical analysis

  std::string passphrase = "did you buy one of therapist reawaken chemists continually gamma pacifies?";

  /**
   * displays the usage line related to configuring chop protocol.
   *
   */
  void display_usage()
  {
    log_warn("chop syntax:\n"
           "\tchop <mode> <up-address> ([<steg> <down-address> --steg-option...])...\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tup_address, down_address ~ host:port\n"
           "\t\tA steganographer is required for each down_address.\n"
           "\t\tsteganographer options follow the steganographer name.\n"
           "\t\tThe down_address list is still required in socks mode.\n"
           "Examples:\n"
           "\tstegotorus chop client 127.0.0.1:5000 "
           "http 192.168.1.99:11253  skype 192.168.1.99:11254 \n"
           "\tstegotorus chop server 127.0.0.1:9005 "
           "http 192.168.1.99:11253  skype 192.168.1.99:11254");
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
  bool user_specified(std::string keyword_option)
  {
    return (chop_user_config.find(keyword_option) != chop_user_config.end());
  }

  /**
   * validate the config by checking for unknown keyword at
   * in chop config*/
  bool valid_config_keyword(const std::string& option_keyword) {
      if ((std::find(arg_option_list.begin(), arg_option_list.end(), option_keyword) == arg_option_list.end()) &&
          (std::find(binary_option_list.begin(), binary_option_list.end(), option_keyword) == binary_option_list.end()))
        return false;

    return true;
  }

  CONFIG_DECLARE_METHODS(chop);

  DISALLOW_COPY_AND_ASSIGN(chop_config_t);
};
}

#endif
