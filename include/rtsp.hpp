#pragma once

#include "crypto.hpp"
#include "plist.hpp"
#include "srp.hpp"
#include <memory>

#define MAX_MSG_BUFFER_SIZE 2048

class RTSPParser {
public:
  RTSPParser(int client_fd, std::shared_ptr<CryptoHandler> crypto_handler);
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
  SRPHandler srpHandler_;
  char header[256];
  std::shared_ptr<CryptoHandler> cryptoHandler_;

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
  int rtsp_post_pair_setup();

  std::vector<uint8_t> create_plist();
};

std::unique_ptr<RTSPParser>
create_rtsp_parser(int client_fd,
                   std::shared_ptr<CryptoHandler> crypto_handler);
