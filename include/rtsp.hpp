#pragma once

#include "audio_control.hpp"
#include "audio_stream.hpp"
#include "crypto.hpp"
#include "event.hpp"
#include "fairplay.hpp"
#include "flags.hpp"
#include "pairing_manager.hpp"
#include "plist_decoder.hpp"
#include "plist_encoder.hpp"
#include "ptp_timing.hpp"
#include "srp.hpp"
#include "tlv8.hpp"
#include <atomic>

#include <memory>
#include <tuple>

#define MAX_MSG_BUFFER_SIZE 2048

class SessionHandler {
public:
  SessionHandler(int client_fd, std::string macAddress, std::string pi,
                 std::shared_ptr<FeatureFlags> featureFlags,
                 std::shared_ptr<StatusFlags> statusFlags,
                 std::shared_ptr<PairingManager> pairingManager);
  ~SessionHandler();

  int set_client(int currentClient);
  int set_msg(char *tcpMessage, int len);
  int parse_message();

  u8Vec_t get_shared_key();

  std::tuple<std::string, u8Vec_t> get_response();

  bool is_verified() { return verified_; };
  bool is_running() { return running_; };

private:
  std::atomic<bool> verified_{false};
  std::atomic<bool> running_{true};
  int clientID_, messageLength_, contentLength_, CSeq_;
  char *body_, *bodyBuffer_, *msg_;
  std::string request_, requestType_, title_, msgHeader_, macAddress_, pi_;
  char header_[256];
  std::string sendHeader_;
  u8Vec_t sendBody_;
  size_t sendHeaderLen_;

  std::unique_ptr<PlistEncoder> plistEncoder_;
  std::unique_ptr<PlistDecoder> plistDecoder_;
  std::unique_ptr<SRPHandler> srpHandler_;
  std::unique_ptr<CryptoHandler> cryptoHandler_;
  std::shared_ptr<FeatureFlags> featureFlags_;
  std::shared_ptr<StatusFlags> statusFlags_;
  std::unique_ptr<TLV8Decoder> tlv8Decoder_;
  std::unique_ptr<TLV8Encoder> tlv8Encoder_;
  std::shared_ptr<PairingManager> pairingManager_;
  std::unique_ptr<FairPlayWrapper> fairPlayWrapper_;
  std::unique_ptr<PTPTimingHandler> ptpHandler_;
  std::unique_ptr<EventHandler> eventHandler_;
  std::unique_ptr<AudioDataHandler> audioDataHandler_;
  std::unique_ptr<AudioControlHandler> audioControlHandler_;

  int get_content_length();
  int get_cseq();
  int reset_state();
  int get_req();
  int get_req_type();
  int get_title();
  int get_body();
  int create_header(std::string applicationType, size_t plistSize);
  int create_header();

  int rtsp_get_options();
  int rtsp_post_commands();
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

  int rtsp_post_fp_setup();
  u8Vec_t fp3_setup_m2();
  u8Vec_t fp3_setup_m3();
  u8Vec_t fp3_setup_m4();

  int rtsp_post_feedback();

  int rtsp_setup();
  u8Vec_t rtsp_setup_m1(pwVal::Dict dictionary);
  u8Vec_t rtsp_setup_m2(pwVal::Dict dictionary);
  u8Vec_t rtsp_setup_m3(pwVal::Dict dictionary);
  u8Vec_t rtsp_setup_media_stream(pwVal::Dict dictionary);

  int rtsp_record();
  int rtsp_get_parameter();
  int rtsp_set_peers();
  int rtsp_post_audiomode();
  int rtsp_set_rate_anchortime();
  int rtsp_teardown();

  int rtsp_empty_message();

  u8Vec_t create_plist();
};

std::shared_ptr<SessionHandler>
create_rtsp_parser(int clientID, std::string macAddress, std::string pi,
                   std::shared_ptr<FeatureFlags> featureFlags,
                   std::shared_ptr<StatusFlags> statusFlags,
                   std::shared_ptr<PairingManager> pairingManager);
