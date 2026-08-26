#include "rtsp.hpp"

#include "airplay_server.hpp"
#include "crypto.hpp"
#include "info_plist.hpp"
#include "plist.hpp"
#include "srp.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <sys/socket.h>
#include <vector>

namespace {
std::vector<uint8_t> encode_tlv8(uint8_t type,
                                 const std::vector<uint8_t> &value) {
  std::vector<uint8_t> out;

  if (value.empty()) {
    out.push_back(type);
    out.push_back(0);
    return out;
  }
  size_t offset = 0;
  while (offset < value.size()) {
    size_t chunk = std::min(value.size() - offset, size_t(255));
    out.push_back(type);
    out.push_back(static_cast<uint8_t>(chunk));
    out.insert(out.end(), value.begin() + offset,
               value.begin() + offset + chunk);
    offset += chunk;
  }

  return out;
}
} // namespace

RTSPParser::RTSPParser(int client_fd,
                       std::shared_ptr<CryptoHandler> cryptoHandler,
                       std::shared_ptr<FeatureFlags> featureFlags,
                       std::shared_ptr<StatusFlags> statusFlags)
    : client_fd_(client_fd), contentLength_(), CSeq_(), msg_{}, plistWriter_(),
      srpHandler_(), header{}, cryptoHandler_(cryptoHandler),
      featureFlags_(featureFlags), statusFlags_(statusFlags) {
  std::cout << "Created RTSP parser, listening to client with ID: " << client_fd
            << std::endl;
}

RTSPParser::~RTSPParser() {}

int RTSPParser::set_client(int currentClient) {
  client_fd_ = currentClient;
  return 0;
}

int RTSPParser::set_msg(char *tcpMessage, int len) {
  // ESP_LOGI(TAG, "Set message with length: %d", len);
  msg_ = tcpMessage;
  messageLength_ = len;
  return 0;
}

int RTSPParser::parse_message() {
  msg_[messageLength_] = '\0';

  reset_state();

  get_content_length();
  get_cseq();
  get_title();
  get_body();

  if (strstr(msg_, "GET /info")) {
    printf("GET /info\n");
    rtsp_get_info();
  } else if (strstr(msg_, "OPTIONS *")) {
    printf("OPTIONS\n");
    rtsp_get_options();
  } else if (strstr(msg_, "POST /command")) {
    printf("POST /command\n");
    rtsp_post_commands();
  } else if (strstr(msg_, "POST /fp-setup")) {
    printf("POST /fp-setup\n");
    rtsp_post_fp_setup();
  } else if (strstr(msg_, "POST /pair-setup")) {
    printf("POST /pair-setup\n");
    rtsp_post_pair_setup();
  } else if (strstr(msg_, "POST /pair-verify")) {
    printf("POST /pair-verify\n");
    rtsp_post_pair_verify();
  }

  memset(msg_, 0, MAX_MSG_BUFFER_SIZE);
  messageLength_ = 0;

  return 0;
}

int RTSPParser::reset_state() {
  CSeq_ = -1;
  contentLength_ = -1;

  return 0;
}

std::vector<uint8_t> RTSPParser::create_plist() {
  using V = PlistWriter::Value;

  auto plist = plistWriter_.serialize(V::dict({
      {"deviceID", V::string(get_system_mac_address())},
      {"features", V::uint(featureFlags_->getRaw())},
      {"model", V::string("AudioAccessory6,1")},
      {"gcgl", V::string("0")},
      // {"pk", V::string(crypto_handler_->get_public_hex_string())},
      {"nameIsFactoryDefault", V::boolean(false)},
      {"pi", V::string("767e31b2-9074-4be0-a3ad-4c0b491877ca")},
      {"protocolVersion", V::string("1.1")},
      {"password", V::boolean(true)},
      {"sourceVersion", V::string("366.0")},
      {"statusFlags", V::uint(statusFlags_->getRaw())},
      // {"audioFormats", V::array({V::dict({
      //                      {"type", V::uint(96)},
      //                      {"audioInputFormats", V::uint(0x01000000)},
      //                      {"audioOutputFormats", V::uint(0x01000000)},
      // })})},
  }));
  return plist;
}

int RTSPParser::rtsp_get_options() {
  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            // "Public: OPTIONS, GET, POST, SETUP, ANNOUNCE, "
                            // "RECORD, PAUSE, FLUSH, TEARDOWN\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "\r\n",
                            CSeq_);

  send(client_fd_, header, header_len, 0);

  std::cout << "Send rtsp get options" << std::endl;
  return 0;
}

int RTSPParser::rtsp_post_commands() {

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Public: OPTIONS, GET, POST, SETUP, ANNOUNCE, "
                            "RECORD, PAUSE, FLUSH, TEARDOWN\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "\r\n",
                            CSeq_);

  send(client_fd_, header, header_len, 0);
  // int header_len = snprintf(header, sizeof(header),
  //                           "RTSP/1.0 200 OK\r\n"
  //                           "CSeq: %d\r\n"
  //                           "Content-Type:
  //                           application/x-apple-binary-plist\r\n"
  //                           "Content-Length: %d\r\n"
  //                           // "Server: AirTunes/366.0\r\n"
  //                           "\r\n",
  //                           CSeq, empty_bplist_len);

  // ssize_t err = send(client_fd, header, header_len, 0);
  // err = send(client_fd, empty_bplist, empty_bplist_len, 0);
  //
  // if (err <= 0)
  //   printf("Error not printing full message");
  //
  // for (size_t i = 0; i < empty_bplist_len; i++)
  //   printf("%02x", empty_bplist[i]);
  // printf("\n");

  return 0;
}

int RTSPParser::rtsp_post_fp_setup() {
  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Public: OPTIONS, GET, POST, SETUP, ANNOUNCE, "
                            "RECORD, PAUSE, FLUSH, TEARDOWN\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "\r\n",
                            CSeq_);

  send(client_fd_, header, header_len, 0);
  return 0;
}

int RTSPParser::rtsp_get_info() {
  std::vector<uint8_t> plist = create_plist();

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "Content-Type: application/x-apple-binary-plist\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)plist.size());

  if (send(client_fd_, header, header_len, 0) < 0)
    std::cerr << "[RTSPParser] Header not sent correctly!" << std::endl;
  if (send(client_fd_, plist.data(), plist.size(), 0) < 0)
    std::cerr << "[RTSPParser] Header not sent correctly!" << std::endl;

  std::cout << header << std::endl;
  for (size_t i = 0; i < plist.size(); i++)
    printf("%02x ", plist[i]);
  std::cout << std::endl;

  return 0;
}

int RTSPParser::rtsp_post_pair_setup() {
  std::vector<uint8_t> body;
  std::vector<uint8_t> stateTLV8 = encode_tlv8(0x06, {0x02});
  std::vector<uint8_t> saltTLV8 = encode_tlv8(0x02, srpHandler_.get_salt());
  std::vector<uint8_t> publicKeyTLV8 =
      encode_tlv8(0x03, srpHandler_.get_public_key());

  std::cout << "Succesfully created TLV8 encodings of State, Salt and PK."
            << std::endl;

  body.insert(body.end(), stateTLV8.begin(), stateTLV8.end());
  body.insert(body.end(), saltTLV8.begin(), saltTLV8.end());
  body.insert(body.end(), publicKeyTLV8.begin(), publicKeyTLV8.end());

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "Content-Type: application/x-apple-binary-plist\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)body.size());

  send(client_fd_, header, header_len, 0);
  send(client_fd_, body.data(), body.size(), 0);
  return 0;
};

int RTSPParser::rtsp_post_pair_verify() {
  uint8_t tlv[] = {0x06, 0x01, 0x02,  // State = M2
                   0x07, 0x01, 0x02}; // Error = Authentication

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)sizeof(tlv));

  send(client_fd_, header, header_len, 0);
  send(client_fd_, tlv, sizeof(tlv), 0);

  return 0;
};

int RTSPParser::get_cseq() {
  const char *cseq = strstr(msg_, "CSeq:");

  if (!cseq)
    return -1;

  sscanf(cseq, "CSeq: %d", &CSeq_);
  return 0;
}

int RTSPParser::get_content_length() {
  const char *len = strstr(msg_, "Content-Length:");

  if (!len)
    return -1;

  sscanf(len, "Content-Length: %d", &contentLength_);

  return 0;
}

int RTSPParser::get_title() {
  const char *lineEnd = strstr(msg_, "\r\n");
  if (!lineEnd)
    return -1;

  title_ = std::string((const char *)msg_, lineEnd);
  return 0;
}

int RTSPParser::get_body() {
  body_ = strstr(msg_, "\r\n\r\n");
  if (!body_)
    return -1;
  body_ += 4;

  size_t headerLength = body_ - msg_;
  int bodyRead = messageLength_ - headerLength;
  int remaining = contentLength_ - bodyRead;

  std::string msgHeader(msg_, headerLength);
  std::cout << msgHeader << std::endl;

  if (remaining < 0)
    return -1;

  if (contentLength_ > MAX_MSG_BUFFER_SIZE) {
    bodyBuffer_ = (char *)malloc(contentLength_);

    memcpy(bodyBuffer_, body_, bodyRead);
    int receivedSize =
        recv(client_fd_, bodyBuffer_ + bodyRead, remaining, MSG_WAITALL);
    bodyBuffer_[contentLength_] = '\0';
    body_ = bodyBuffer_;

    free(bodyBuffer_);

    remaining -= receivedSize;
  } else if (remaining > 0) {
    int receivedSize =
        recv(client_fd_, body_ + bodyRead, remaining, MSG_WAITALL);
    remaining -= receivedSize;
    bodyRead += receivedSize;
  }
  for (size_t i = 0; i < uint(bodyRead); i++)
    printf("%02x ", (unsigned char)body_[i]);
  printf("\n");

  return 0;
}

std::unique_ptr<RTSPParser>
create_rtsp_parser(int client_fd, std::shared_ptr<CryptoHandler> cryptoHandler,
                   std::shared_ptr<FeatureFlags> featureFlags,
                   std::shared_ptr<StatusFlags> statusFlags) {
  return std::make_unique<RTSPParser>(client_fd, cryptoHandler, featureFlags,
                                      statusFlags);
}
