#pragma once

#include "crypto.hpp"
#include "flags.hpp"
#include "pairing-manager.hpp"
#include "plist.hpp"
#include "srp.hpp"
#include "tlv8.hpp"
#include <atomic>

#include <memory>
#include <vector>

#define MAX_MSG_BUFFER_SIZE 2048

class RTSPParser {
public:
  RTSPParser(int client_fd, std::string macAddress, std::string pi,
             std::shared_ptr<FeatureFlags> featureFlags,
             std::shared_ptr<StatusFlags> statusFlags,
             std::shared_ptr<PairingManager> pairingManager);
  ~RTSPParser();

  int set_client(int currentClient);
  int set_msg(char *tcpMessage, int len);
  int parse_message();
  bool is_verified() { return verified_; };
  u8Vec_t get_shared_key();

private:
  std::atomic<bool> verified_{false};
  int clientID_, messageLength_, contentLength_, CSeq_;
  char *body_, *bodyBuffer_, *msg_;
  std::string title_, msgHeader_, macAddress_, pi_;
  PlistWriter plistWriter_;
  char header[256];

  std::unique_ptr<SRPHandler> srpHandler_;
  std::unique_ptr<CryptoHandler> cryptoHandler_;
  std::shared_ptr<FeatureFlags> featureFlags_;
  std::shared_ptr<StatusFlags> statusFlags_;
  std::unique_ptr<TLV8Decoder> tlv8Decoder_;
  std::unique_ptr<TLV8Encoder> tlv8Encoder_;
  std::shared_ptr<PairingManager> pairingManager_;

  int get_content_length();
  int get_cseq();
  int reset_state();
  int get_title();
  int get_body();
  int rtsp_get_options();
  int rtsp_post_commands();
  int rtsp_post_fp_setup();
  int rtsp_get_info();

  int rtsp_post_pair_verify();
  int pair_verify_m2();
  int pair_verify_m3();
  int pair_verify_m4();

  int rtsp_post_pair_error();

  int rtsp_post_pair_setup();
  int pair_setup_m2();
  int pair_setup_m4();
  int pair_setup_m5();
  int pair_setup_m6();

  int rtsp_decrypt_message();

  u8Vec_t create_plist();
};

std::shared_ptr<RTSPParser>
create_rtsp_parser(int clientID, std::string macAddress, std::string pi,
                   std::shared_ptr<FeatureFlags> featureFlags,
                   std::shared_ptr<StatusFlags> statusFlags,
                   std::shared_ptr<PairingManager> pairingManager);
