#include "rtsp.hpp"

#include "airplay_server.hpp"
#include "crypto.hpp"
#include "info_plist.hpp"
#include "pairing-manager.hpp"
#include "plist.hpp"
#include "srp.hpp"
#include "tlv8.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <sys/socket.h>
#include <vector>

RTSPParser::RTSPParser(int client_fd,
                       std::shared_ptr<CryptoHandler> cryptoHandler,
                       std::shared_ptr<FeatureFlags> featureFlags,
                       std::shared_ptr<StatusFlags> statusFlags)
    : client_fd_(client_fd), contentLength_(), CSeq_(), msg_{}, plistWriter_(),
      header{}, cryptoHandler_(cryptoHandler), featureFlags_(featureFlags),
      statusFlags_(statusFlags) {
  std::cout << "Created RTSP parser, listening to client with ID: " << client_fd
            << std::endl;
  tlv8Decoder_ = create_tlv8_decoder();
  tlv8Encoder_ = create_tlv8_encoder();
  srpHandler_ = create_srp_handler();
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
    rtsp_get_info();
  } else if (strstr(msg_, "OPTIONS *")) {
    rtsp_get_options();
  } else if (strstr(msg_, "POST /command")) {
    rtsp_post_commands();
  } else if (strstr(msg_, "POST /fp-setup")) {
    rtsp_post_fp_setup();
  } else if (strstr(msg_, "POST /pair-setup")) {
    rtsp_post_pair_setup();
  } else if (strstr(msg_, "POST /pair-verify")) {
    rtsp_post_pair_verify();
  } else {
    std::cout << msg_ << std::endl;
    std::cout << "[RTSPParser] Unknown or encrypted message received! Lengte: "
              << messageLength_ << std::endl;
    std::cout << "Ruwe hex data:" << std::endl;
    for (int i = 0; i < messageLength_; i++) {
      printf("%02x ", (unsigned char)msg_[i]);
      // Print maximaal de eerste 64 bytes om je terminal overzichtelijk te
      // houden
    }
    printf("\n");
  }
  printf("\n");

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

  return 0;
}

int RTSPParser::rtsp_post_pair_setup() {
  tlv8Decoder_->reinterpret_message((const char *)body_, contentLength_);
  tlv8Decoder_->decode();
  auto tlv8State = tlv8Decoder_->read_message(TLV8_STATE);

  std::cout << "Decoding message." << std::endl;

  int err = 0;

  if (tlv8State.size() != 1) {
    err = -1;
    std::cerr << "Method size is not correct." << std::endl;
    rtsp_post_pair_error();

    return err;
  }

  std::vector<uint8_t> body;
  uint8_t currentState = tlv8Decoder_->read_message(TLV8_STATE)[0];

  printf("Method: %02x\n", currentState);

  switch (currentState) {

  case 0x01:
    err = pair_setup_m2();

    break;
  case 0x03:
    err = pair_setup_m4();

    break;
  case 0x05:
    err = pair_setup_m5();
    err = pair_setup_m6();

    break;
  }

  if (err < 0) {
    std::cout << "Encountered Error, sending error message" << std::endl;
    rtsp_post_pair_error();
    return -1;
  }

  body = tlv8Encoder_->get_body();

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "Content-Type: application/pairing+tlv8\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)body.size());

  std::cout << "Sending state: " << std::hex << currentState + 1 << std::endl;

  err = send(client_fd_, header, header_len, 0);
  err = send(client_fd_, body.data(), body.size(), 0);

  if (err < 0) {
    std::cerr << "Could not send message." << std::endl;
    return -1;
  }

  return 0;
};

int RTSPParser::pair_setup_m2() {
  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap = {
      {TLV8_STATE, {0x02}},
      {TLV8_SALT, srpHandler_->get_salt()},
      {TLV8_PK, srpHandler_->get_public_key()}};
  int err = tlv8Encoder_->set_map(messageMap);
  err = tlv8Encoder_->encode();

  if (err < 0) {
    std::cerr << "Error encoding M2 message." << std::endl;
    return -1;
  }
  return 0;
}

int RTSPParser::pair_setup_m4() {
  int err = srpHandler_->set_A(tlv8Decoder_->read_message(TLV8_PK));
  err = srpHandler_->set_M1(tlv8Decoder_->read_message(TLV8_PROOF));
  if (err < 0) {
    rtsp_post_pair_error();
    throw std::runtime_error("Error setting BigNum values");
  }

  std::cout << "Set M4 values." << std::endl;

  srpHandler_->client_proof();
  if (!srpHandler_->validate_M1()) {
    std::cout << "Error: M1 server and M1 client are not the same" << std::endl;
    rtsp_post_pair_error();

    return -1;
  }

  err = srpHandler_->create_M2();
  if (err < 0) {
    rtsp_post_pair_error();
    return err;
  }

  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap = {
      {TLV8_STATE, {0x04}},
      // {TLV8_PK, srpHandler_->get_public_key()},
      {TLV8_PROOF, srpHandler_->get_proof()},
  };

  err = tlv8Encoder_->set_map(messageMap);
  err = tlv8Encoder_->encode();

  if (err < 0) {
    std::cerr << "Error encoding M2 message." << std::endl;
    rtsp_post_pair_error();
    return err;
  }

  return err;
}

int RTSPParser::pair_setup_m5() {
  pairingManager_ = create_pairing_manager();
  hapHandler_ = create_hap_handler(srpHandler_->get_session_key());

  int err = hapHandler_->hkdf_sha512("Pair-Setup-Encrypt-Salt",
                                     "Pair-Setup-Encrypt-Info");

  err = hapHandler_->set_nonce("PS-Msg05");

  hapHandler_->set_cipher_tag(tlv8Decoder_->read_message(TLV8_ENCRYPTED_DATA));
  std::vector<uint8_t> blob = hapHandler_->chacha_decrypt();

  tlv8Decoder_->set_sub_message(blob);
  tlv8Decoder_->decode_sub();

  err = hapHandler_->hkdf_sha512("Pair-Setup-Controller-Sign-Salt",
                                 "Pair-Setup-Controller-Sign-Info");

  int ok = hapHandler_->M5_verification(
      tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER),
      tlv8Decoder_->read_sub_message(TLV8_PK),
      tlv8Decoder_->read_sub_message(TLV8_SIGNATURE));

  if (!ok) {
    std::cerr << "M5 Verification not OK. Quitting." << std::endl;
    rtsp_post_pair_error();

    return -1;
  }

  pairingManager_->add_paired_device(
      {tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER),
       {tlv8Decoder_->read_sub_message(TLV8_PK),
        tlv8Decoder_->read_sub_message(TLV8_SIGNATURE)}});

  return err;
}

int RTSPParser::pair_setup_m6() {
  int err = hapHandler_->hkdf_sha512("Pair-Setup-Accessory-Sign-Salt",
                                     "Pair-Setup-Accessory-Sign-Info");

  err = hapHandler_->set_nonce("PS-Msg06");

  return err;
}

int RTSPParser::rtsp_post_pair_verify() {
  std::cerr << "Encountered error, authentication error." << std::endl;
  uint8_t tlv[] = {0x06, 0x01, 0x02,  // State = M2
                   0x07, 0x01, 0x02}; // Error = Authentication

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Content-Type: application/pairing+tlv8\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)sizeof(tlv));

  send(client_fd_, header, header_len, 0);
  send(client_fd_, tlv, sizeof(tlv), 0);

  return 0;
};

int RTSPParser::rtsp_post_pair_error() {
  uint8_t tlv[] = {0x06, 0x01, 0x02,  // State = M2
                   0x07, 0x01, 0x02}; // Error = Authentication

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Content-Type: application/pairing+tlv8\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)sizeof(tlv));

  send(client_fd_, header, header_len, 0);
  send(client_fd_, tlv, sizeof(tlv), 0);

  return 0;
}

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
