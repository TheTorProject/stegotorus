#include <vector>
#include <string>
#include <algorithm>
#include <yaml-cpp/yaml.h>

#include "util.h"
#include "rng.h"

#include "connections.h"
#include "steg.h"

#include "modus_operandi.h"

#include "chop_config.h"
#include "chop_circuit.h"

using std::vector;
using std::string;
using std::make_pair;
// Configuration methods
namespace chop_protocol {

  chop_config_t::chop_config_t()
  : total_transmited_data_bytes(0),
    total_transmited_cover_bytes(1),
    handshake_encryptor(NULL),
    handshake_decryptor(NULL),
    transparent_proxy(NULL)
                                    //just to evade div by 0
{
  ignore_socks_destination = true;
  trace_packets = false;
  trace_packet_data = true;
  encryption = true;
  retransmit = true;
  noise2signal = 0;
}

chop_config_t::~chop_config_t()
{
  if (up_address)
    evutil_freeaddrinfo(up_address);
  for (vector<struct evutil_addrinfo *>::iterator i = down_addresses.begin();
       i != down_addresses.end(); i++)
    evutil_freeaddrinfo(*i);

  for (vector<steg_config_t *>::iterator i = steg_targets.begin();
       i != steg_targets.end(); i++)
    delete *i;

  for (chop_circuit_table::iterator i = circuits.begin();
       i != circuits.end(); i++)
    if (i->second)
      delete i->second;

  delete transparent_proxy;
  delete handshake_encryptor;
  delete handshake_decryptor;
  
}

bool
chop_config_t::init_from_protocol_config_dict() {
  const char* defport;
  bool listen_up;

  //this also verify that the config dict is already populated
  if (chop_user_config["mode"] == "client") {
    defport = "48988"; // bf5c
    mode = LSN_SIMPLE_CLIENT;
    listen_up = true;
  } else if (chop_user_config["mode"] == "socks") {
    defport = "23548"; // 5bf5
    mode = LSN_SOCKS_CLIENT;
    listen_up = true;
  } else if (chop_user_config["mode"] == "server") {
    defport = "11253"; // 2bf5
    mode = LSN_SIMPLE_SERVER;
    listen_up = false;
  } else {
    log_warn("invalid mode %s for protocol chop", chop_user_config["mode"].c_str());
    return false;
  }

  vector<string> addresses;

  //Try recover upaddress from where the mode was retrieved. 
  up_address = resolve_address_port(chop_user_config["up-address"].c_str(), 1, listen_up, defport);

  if (!up_address) {
    log_warn("chop: invalid up address: %s", chop_user_config["up-address"].c_str());
    return false;

  }

  if (user_specified("server-key")) {
    // accept and ignore (for now) client only
    if (mode == LSN_SIMPLE_SERVER) {
      log_warn("server-key option is not valid in server mode");
      return false;
      }
  }

  if (user_specified("passphrase")) {
    passphrase = chop_user_config["passphrase"];
  }

  if (user_specified("trace-packets")) {
    trace_packets = (modus_operandi_t::uniformize_boolean_value(chop_user_config["trace-packets"]) == true_string);
    log_enable_timestamps();
  }

  if (user_specified("disable-encryption")) {
    encryption = false;
  }

  if (user_specified("disable-retransmit")) {
    retransmit = false;
  }

  if (user_specified("enable-retransmit")) {
    retransmit = true;
  }

  if (user_specified("minimum-noise-to-signal")) {
    noise2signal = atoi(chop_user_config["minimum-noise-to-signal"].c_str());
  }

  if (user_specified("cover-server")) {
      cover_server_address = chop_user_config["cover-server"];
      transparent_proxy = new TransparentProxy(base, cover_server_address);
      //This is not related to an specific steg module hence, we store it under
      //"protocol" tag
      steg_mod_user_configs["protocol"]["cover-server"] = cover_server_address;
  }

  //init the header encryptor and the decryptor
  init_handshake_encryption();

  return true;

}

/**
 * read the hierechical struture of the protocol from the YAML configs
 * and store them in the chop_user_config and the steg mods confs. 
 * abort if config has problem.
 *
 * @param protocols_node the YAML node which points to protocols:
 *        node in the config file
 */
bool chop_config_t::init(const YAML::Node& protocol_node)
{
  std::vector<YAML::Node> steg_conf_list; //to store the steg config
  //to be send to the steg mods during creation
  try {
      for(auto cur_protocol_field: protocol_node) {
        //if it is the protocol stegs config we need to store the config node
        //to create the steg protocol later, cause the steg protocol might
        //need access to the protocol options
        std::string current_field_name = cur_protocol_field.first.as<std::string>();
        if (current_field_name == "stegs") {
          for(auto cur_steg: cur_protocol_field.second)
            steg_conf_list.push_back(cur_steg);
        } else {
          if (!valid_config_keyword(current_field_name))
            {
              log_warn("invalid config keyword %s", current_field_name.c_str());
              return false;
            }

          chop_user_config[current_field_name] = cur_protocol_field.second.as<std::string>();      }
      }
  }  catch( YAML::RepresentationException &e ) {
    log_warn("bad config format %s", ((string)e.what()).c_str());
    display_usage();

    return false;

  }

  if (!init_from_protocol_config_dict())
    return false;

  bool listen_down = (mode == LSN_SIMPLE_SERVER);
  //now we are ready to process the stegs node
  if (!(steg_conf_list.size() > 0)) {
    log_warn("chop: no steganographer is specied. at least one steganographer is needed.");
  }

  try {
    for(auto cur_steg : steg_conf_list) {
      struct evutil_addrinfo *addr =
        resolve_address_port(cur_steg["down-address"].as<std::string>().c_str(), 1, listen_down, NULL);
      if (!addr) {
        log_warn("chop: invalid down address: %s", cur_steg["down-address"].as<std::string>().c_str());
        display_usage();
        return false;
      }
      down_addresses.push_back(addr);

      if (!steg_is_supported(cur_steg["name"].as<std::string>().c_str())) {
        log_warn("chop: steganographer '%s' not supported", cur_steg["name"].as<std::string>().c_str());
        display_usage();
        return false;
      }

      steg_targets.push_back(steg_new(cur_steg["name"].as<std::string>().c_str(), this, cur_steg));
    }

  } catch( YAML::RepresentationException &e ) {
    log_warn("bad config format %s", ((string)e.what()).c_str());
    display_usage();

    return false;
  }

  return true;

}


bool chop_config_t::init(unsigned int n_options, const char *const *options)
{

  if (n_options < 2)
    {
      log_warn("you need to at least specify mode of operation and upstream ip address");
      display_usage();
      return false;

    }

  chop_user_config["mode"] = options[0];

  while (options[1][0] == '-') {
    if (strlen(options[1]) < 2)
      {
        log_warn("chop: long option %s should be specifed with -- rather than - :", options[1]);
        display_usage();
        return false;
      }

      if (std::find(arg_option_list.begin(), arg_option_list.end(), options[1] + strlen("--")) != arg_option_list.end())
      {
        if (n_options <= 2) {
          log_warn("chop: option %s requires a value argument", options[1]);
          display_usage();
          return false;

        }

        chop_user_config[options[1]+strlen("--")] = options[2];

        options++;
        n_options--;
      } else if ((std::find(binary_option_list.begin(), binary_option_list.end(), options[1] + strlen("--")) != binary_option_list.end()))
      {
        chop_user_config[options[1]+strlen("--")] = "true";
      } else {
        log_warn("chop: unrecognized option '%s'", options[1]);
        display_usage();
        return false;
      }

      options++;
      n_options--;
  }

  //immidiately after options user needs to specifcy upstream address
  chop_user_config["up-address"] = options[1];
   
  if (!init_from_protocol_config_dict())
    return false;

  bool listen_down = (mode == LSN_SIMPLE_SERVER);

  // From here on out, arguments are blocks of steg target downsteam
  // addresse and its options
  // we are creating the steg config here cause we are using differnt
  // constructor for command line options vs YAML node
  unsigned int cur_op = 2;
  while(cur_op < n_options) {
    if (!steg_is_supported(options[cur_op])) {
      log_warn("chop: steganographer '%s' not supported", options[cur_op]);
      display_usage();
      return false;
    }
    const char* cur_steg_name = options[cur_op];

    cur_op++;
    if (!(cur_op < n_options)) {
      log_warn("chop: missing down stream address for steganographer %s", cur_steg_name);
      display_usage();
      return false;
    }

    struct evutil_addrinfo *addr =
      resolve_address_port(options[cur_op], 1, listen_down, NULL);
    if (!addr) {
      log_warn("chop: invalid down address: %s", options[cur_op]);
      display_usage();
      return false;
    }
    down_addresses.push_back(addr);
    cur_op++;
    //from now on till we reach another steg, all
    //all the options of the curren steg
    std::vector<std::string> steg_option_list;
    while(cur_op < n_options && (!steg_is_supported(options[cur_op]))) {
      steg_option_list.push_back(options[cur_op]);
      cur_op++;
    }

    steg_targets.push_back(steg_new(cur_steg_name, this, steg_option_list));

  }

  return true;

}

struct evutil_addrinfo *
chop_config_t::get_listen_addrs(size_t n) const
{
  if (mode == LSN_SIMPLE_SERVER) {
    if (n < down_addresses.size())
      return down_addresses[n];
  } else {
    if (n == 0)
      return up_address;
  }
  return 0;
}

struct evutil_addrinfo *
chop_config_t::get_target_addrs(size_t n) const
{
  if (mode == LSN_SIMPLE_SERVER) {
    if (n == 0)
      return up_address;
  } else {
    if (n < down_addresses.size())
      return down_addresses[n];
  }
  return NULL;
}

const steg_config_t *
chop_config_t::get_steg(size_t n) const
{
  if (n < steg_targets.size())
    return steg_targets[n];
  return NULL;
}

// Circuit methods

void
chop_config_t::init_handshake_encryption()
{
  key_generator *kgen = 0;

  if (encryption)
    kgen = key_generator::from_passphrase((const uint8_t *)passphrase.data(),
                                          passphrase.length(),
                                          0, 0, 0, 0);
  if (mode == LSN_SIMPLE_SERVER) {
    if (encryption) {
      handshake_decryptor = ecb_decryptor::create(kgen, 16);
    } else {
      handshake_decryptor = ecb_decryptor::create_noop();
    }
  } else {
    if (encryption) {
      handshake_encryptor = ecb_encryptor::create(kgen, 16);
    } else {
      handshake_encryptor = ecb_encryptor::create_noop();
    }
  }

  delete kgen;

}

circuit_t *
chop_config_t::circuit_create(size_t)
{
  chop_circuit_t *ckt = new chop_circuit_t(retransmit);
  ckt->config = this;

  key_generator *kgen = 0;

  if (encryption)
    kgen = key_generator::from_passphrase((const uint8_t *)passphrase.data(),
                                          passphrase.length(),
                                          0, 0, 0, 0);

  if (mode == LSN_SIMPLE_SERVER) {
    if (encryption) {
      ckt->send_crypt     = gcm_encryptor::create(kgen, 16);
      ckt->send_hdr_crypt = ecb_encryptor::create(kgen, 16);
      ckt->recv_crypt     = gcm_decryptor::create(kgen, 16);
      ckt->recv_hdr_crypt = ecb_decryptor::create(kgen, 16);
    } else {
      ckt->send_crypt     = gcm_encryptor::create_noop();
      ckt->send_hdr_crypt = ecb_encryptor::create_noop();
      ckt->recv_crypt     = gcm_decryptor::create_noop();
      ckt->recv_hdr_crypt = ecb_decryptor::create_noop();
    }
  } else {
    if (encryption) {
      ckt->recv_crypt     = gcm_decryptor::create(kgen, 16);
      ckt->recv_hdr_crypt = ecb_decryptor::create(kgen, 16);
      ckt->send_crypt     = gcm_encryptor::create(kgen, 16);
      ckt->send_hdr_crypt = ecb_encryptor::create(kgen, 16);
    } else {
      ckt->recv_crypt     = gcm_decryptor::create_noop();
      ckt->recv_hdr_crypt = ecb_decryptor::create_noop();
      ckt->send_crypt     = gcm_encryptor::create_noop();
      ckt->send_hdr_crypt = ecb_encryptor::create_noop();
    }

    std::pair<chop_circuit_table::iterator, bool> out;
    do {
      do {
        rng_bytes((uint8_t *)&ckt->circuit_id, sizeof(ckt->circuit_id));
      } while (!ckt->circuit_id);

      out = circuits.insert(make_pair(ckt->circuit_id, (chop_circuit_t *)0));
    } while (!out.second);

    out.first->second = ckt;
  }

  delete kgen;
  return ckt;
}

/** This has to be here for the unfortunate macro game 
    inline is added so gcc ignore the Wunused-function warning */
inline chop_circuit_t::chop_circuit_t()
  :chop_circuit_t::chop_circuit_t(true)
{
  //MEANT_TO_BE_UNUSED
  
}
}
