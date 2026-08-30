#pragma once

#include "crypto.hpp"
#include "flags.hpp"
#include "hap_crypto.hpp"
#include "pairing-manager.hpp"
#include "plist.hpp"
#include "srp.hpp"
#include "tlv8.hpp"

#include <memory>

#define MAX_MSG_BUFFER_SIZE 2048

class RTSPParser {
public:
  RTSPParser(int client_fd, std::shared_ptr<CryptoHandler> cryptoHandler,
             std::shared_ptr<FeatureFlags> featureFlags,
             std::shared_ptr<StatusFlags> statusFlags);
  ~RTSPParser();

  int set_client(int currentClient);
  int set_msg(char *tcpMessage, int len);
  int parse_message();

private:
  int client_fd_;
  int messageLength_;
  int contentLength_;
  int CSeq_;
  char *body_;
  char *bodyBuffer_;
  char *msg_;
  std::string title_;
  std::string msgHeader_;
  PlistWriter plistWriter_;
  char header[256];

  std::unique_ptr<HAPCrypto> hapHandler_;
  std::unique_ptr<SRPHandler> srpHandler_;
  std::shared_ptr<CryptoHandler> cryptoHandler_;
  std::shared_ptr<FeatureFlags> featureFlags_;
  std::shared_ptr<StatusFlags> statusFlags_;
  std::unique_ptr<TLV8Decoder> tlv8Decoder_;
  std::unique_ptr<TLV8Encoder> tlv8Encoder_;
  std::unique_ptr<PairingManager> pairingManager_;

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
  int rtsp_post_pair_error();
  int rtsp_post_pair_setup();
  int pair_setup_m2();
  int pair_setup_m4();
  int pair_setup_m5();
  int pair_setup_m6();

  std::vector<uint8_t> create_plist();
};

std::unique_ptr<RTSPParser>
create_rtsp_parser(int client_fd, std::shared_ptr<CryptoHandler> cryptoHandler,
                   std::shared_ptr<FeatureFlags> featureFlags,
                   std::shared_ptr<StatusFlags> statusFlags);
