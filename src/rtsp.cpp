#include "rtsp.hpp"

#include "crypto.hpp"
#include "info_plist.hpp"
#include "pairing-manager.hpp"
#include "plist.hpp"
#include "srp.hpp"
#include "tlv8.hpp"
#include "utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <sys/socket.h>
#include <utility>
#include <vector>

RTSPParser::RTSPParser(int client_fd, std::string macAddress, std::string pi,
                       std::shared_ptr<FeatureFlags> featureFlags,
                       std::shared_ptr<StatusFlags> statusFlags)
    : clientID_(client_fd), contentLength_(), CSeq_(), msg_{},
      macAddress_(macAddress), pi_(pi), plistWriter_(), header{},
      featureFlags_(featureFlags), statusFlags_(statusFlags) {
  std::cout << "Created RTSP parser, listening to client with ID: " << client_fd
            << std::endl;
  tlv8Decoder_ = create_tlv8_decoder();
  tlv8Encoder_ = create_tlv8_encoder();
  cryptoHandler_ = create_crypto_handler();
  pairingManager_ = create_pairing_manager();
  srpHandler_ = create_srp_handler();
}

RTSPParser::~RTSPParser() {}

int RTSPParser::set_client(int currentClient) {
  clientID_ = currentClient;
  return 1;
}

int RTSPParser::set_msg(char *tcpMessage, int len) {
  // ESP_LOGI(TAG, "Set message with length: %d", len);
  msg_ = tcpMessage;
  messageLength_ = len;
  return 1;
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
    std::cout << "/fp-setup" << std::endl;
    rtsp_post_fp_setup();
  } else if (strstr(msg_, "POST /pair-setup")) {
    std::cout << "/pair-setup" << std::endl;
    rtsp_post_pair_setup();
  } else if (strstr(msg_, "POST /pair-verify")) {
    std::cout << "/pair-verify" << std::endl;
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

  return 1;
}

int RTSPParser::reset_state() {
  CSeq_ = -1;
  contentLength_ = -1;

  return 1;
}

std::vector<uint8_t> RTSPParser::create_plist() {
  using V = PlistWriter::Value;

  auto plist = plistWriter_.serialize(V::dict({
      {"deviceID", V::string(macAddress_)},
      {"features", V::uint(featureFlags_->getRaw())},
      {"model", V::string("AudioAccessory6,1")},
      {"gcgl", V::string("0")},
      // {"pk", V::string(crypto_handler_->get_public_hex_string())},
      {"nameIsFactoryDefault", V::boolean(false)},
      {"pi", V::string(pi_)},
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

  send(clientID_, header, header_len, 0);

  std::cout << "Send rtsp get options" << std::endl;
  return 1;
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

  send(clientID_, header, header_len, 0);
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

  return 1;
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

  send(clientID_, header, header_len, 0);
  return 1;
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

  if (send(clientID_, header, header_len, 0) < 0)
    std::cerr << "[RTSPParser] Header not sent correctly!" << std::endl;
  if (send(clientID_, plist.data(), plist.size(), 0) < 0)
    std::cerr << "[RTSPParser] Header not sent correctly!" << std::endl;

  return 1;
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

  if (err <= 0) {
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

  std::cout << header << std::endl;
  for (auto c : body)
    std::cout << chars_to_hex({c}) << " ";

  std::cout << std::endl;

  err = send(clientID_, header, header_len, 0);
  err = send(clientID_, body.data(), body.size(), 0);

  if (err <= 0) {
    std::cerr << "Could not send message." << std::endl;
    return -1;
  }

  return 1;
};

int RTSPParser::pair_setup_m2() {
  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap = {
      {TLV8_STATE, {0x02}},
      {TLV8_SALT, srpHandler_->get_salt()},
      {TLV8_PK, srpHandler_->get_public_key()}};

  int err = tlv8Encoder_->set_map(messageMap);
  err = tlv8Encoder_->encode();

  if (err <= 0) {
    std::cerr << "Error encoding M2 message." << std::endl;
    return -1;
  }
  return 1;
}

int RTSPParser::pair_setup_m4() {
  int err = srpHandler_->set_A(tlv8Decoder_->read_message(TLV8_PK));
  err = srpHandler_->set_M1(tlv8Decoder_->read_message(TLV8_PROOF));
  if (err <= 0) {
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
  if (err <= 0) {
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

  if (err <= 0) {
    std::cerr << "Error encoding SRP M2 message." << std::endl;
    rtsp_post_pair_error();
    return err;
  }

  cryptoHandler_->set_session_key(srpHandler_->get_session_key());

  return err;
}

int RTSPParser::pair_setup_m5() {
  int err = cryptoHandler_->hkdf_sha512("Pair-Setup-Encrypt-Salt",
                                        "Pair-Setup-Encrypt-Info");

  cryptoHandler_->set_encrypt_key(cryptoHandler_->get_hkdf_key());

  err = cryptoHandler_->set_nonce("PS-Msg05");

  cryptoHandler_->set_cipher_tag(
      tlv8Decoder_->read_message(TLV8_ENCRYPTED_DATA));
  std::vector<uint8_t> blob = cryptoHandler_->chacha_decrypt();

  tlv8Decoder_->set_sub_message(blob);
  tlv8Decoder_->decode_sub();

  err = cryptoHandler_->hkdf_sha512("Pair-Setup-Controller-Sign-Salt",
                                    "Pair-Setup-Controller-Sign-Info");

  std::vector<uint8_t> messageInfo;
  auto hkdfKey = cryptoHandler_->get_hkdf_key();
  auto id = tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER);
  auto pubKey = tlv8Decoder_->read_sub_message(TLV8_PK);

  messageInfo.insert(messageInfo.end(), hkdfKey.begin(), hkdfKey.end());
  messageInfo.insert(messageInfo.end(), id.begin(), id.end());
  messageInfo.insert(messageInfo.end(), pubKey.begin(), pubKey.end());

  int ok = cryptoHandler_->signature_verification(
      messageInfo, pubKey, tlv8Decoder_->read_sub_message(TLV8_SIGNATURE));

  if (ok != 1) {
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
  int err = cryptoHandler_->hkdf_sha512("Pair-Setup-Accessory-Sign-Salt",
                                        "Pair-Setup-Accessory-Sign-Info");

  err = cryptoHandler_->set_accessory_x(cryptoHandler_->get_hkdf_key());
  err = cryptoHandler_->set_signature(cryptoHandler_->get_accessory_x(),
                                      cryptoHandler_->get_identifier(),
                                      cryptoHandler_->get_public_key());

  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> subMessageMap = {
      {TLV8_IDENTIFIER, cryptoHandler_->get_identifier()},
      {TLV8_PK, cryptoHandler_->get_public_key()},
      {TLV8_SIGNATURE, cryptoHandler_->get_signature()},
  };

  tlv8Encoder_->set_map(subMessageMap);
  tlv8Encoder_->encode();

  err = cryptoHandler_->set_nonce("PS-Msg06");

  auto subEncryptedSubmessage =
      cryptoHandler_->chacha_encrypt(tlv8Encoder_->get_body());

  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap = {
      {TLV8_STATE, {0x06}},
      {TLV8_ENCRYPTED_DATA, subEncryptedSubmessage},
  };

  tlv8Encoder_->set_map(messageMap);
  tlv8Encoder_->encode();

  return err;
}

int RTSPParser::rtsp_post_pair_verify() {
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

    // rtsp_post_pair_error();
    err = pair_verify_m2();

    break;
  case 0x03:
    err = pair_verify_m3();
    if (err <= 0) {
      std::cerr << "Error during verification of M3 message" << std::endl;
      return -1;
    }

    err = pair_verify_m4();

    break;
  }

  if (err <= 0) {
    std::cout << "Encountered Error, sending error message" << std::endl;
    rtsp_post_pair_error();
    return -1;
  }

  body = tlv8Encoder_->get_body();

  int header_len = snprintf(header, sizeof(header),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "Connection: keep-alive\r\n"
                            "Content-Type: application/pairing+tlv8\r\n"
                            "Content-Length: %d\r\n"
                            "\r\n",
                            CSeq_, (int)body.size());

  std::cout << header << std::endl;
  for (auto c : body)
    std::cout << chars_to_hex({c}) << " ";

  std::cout << std::endl;

  std::cout << "Sending state: " << std::hex << currentState + 1 << std::endl;

  std::vector<uint8_t> fullMessage(header, header + header_len);
  fullMessage.insert(fullMessage.end(), body.begin(), body.end());

  err = send(clientID_, fullMessage.data(), fullMessage.size(), 0);

  if (err <= 0) {
    std::cerr << "Could not send message." << std::endl;
    return -1;
  }

  return 1;
};

int RTSPParser::pair_verify_m2() {
  cryptoHandler_->set_client_ephemeral_pub(tlv8Decoder_->read_message(TLV8_PK));
  cryptoHandler_->calculate_shared_key();

  cryptoHandler_->set_signature(cryptoHandler_->get_ephemeral_key(),
                                cryptoHandler_->get_identifier(),
                                cryptoHandler_->get_client_ephemeral_key());

  cryptoHandler_->set_encrypt_key(cryptoHandler_->get_shared_key());

  cryptoHandler_->hkdf_sha512("Pair-Verify-Encrypt-Salt",
                              "Pair-Verify-Encrypt-Info");

  cryptoHandler_->set_encrypt_key(cryptoHandler_->get_hkdf_key());

  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> subMessageMap = {
      {TLV8_IDENTIFIER, cryptoHandler_->get_identifier()},
      {TLV8_SIGNATURE, cryptoHandler_->get_signature()},
  };

  tlv8Encoder_->set_map(subMessageMap);
  tlv8Encoder_->encode();

  cryptoHandler_->set_nonce("PV-Msg02");

  auto encryptedSubMessage =
      cryptoHandler_->chacha_encrypt(tlv8Encoder_->get_body());

  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap = {
      {TLV8_STATE, {0x02}},
      {TLV8_PK, cryptoHandler_->get_ephemeral_key()},
      {TLV8_ENCRYPTED_DATA, encryptedSubMessage},
  };

  tlv8Encoder_->set_map(messageMap);
  tlv8Encoder_->encode();

  return 1;
}

int RTSPParser::pair_verify_m3() {
  int err = cryptoHandler_->set_nonce("PV-Msg03");
  cryptoHandler_->set_cipher_tag(
      tlv8Decoder_->read_message(TLV8_ENCRYPTED_DATA));

  auto decryptBlob = cryptoHandler_->chacha_decrypt();
  tlv8Decoder_->set_sub_message(decryptBlob);
  tlv8Decoder_->decode_sub();

  auto [exists, pubKey] = pairingManager_->get_device_key(
      tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER));

  if (!exists) {
    std::cerr << "Connecting device does not exist yet. Returning error."
              << std::endl;
    return -1;
  }

  std::vector<uint8_t> messageInfo;
  auto clientEph = cryptoHandler_->get_client_ephemeral_key();
  auto id = tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER);
  auto serverEph = cryptoHandler_->get_ephemeral_key();

  messageInfo.insert(messageInfo.end(), clientEph.begin(), clientEph.end());
  messageInfo.insert(messageInfo.end(), id.begin(), id.end());
  messageInfo.insert(messageInfo.end(), serverEph.begin(), serverEph.end());

  err = cryptoHandler_->signature_verification(
      messageInfo, pubKey, tlv8Decoder_->read_sub_message(TLV8_SIGNATURE));

  if (err <= 0) {
    std::cerr << "Error verifying client ephemeral key" << std::endl;
    return err;
  }

  return err;
}

int RTSPParser::pair_verify_m4() {

  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap = {
      {TLV8_STATE, {0x04}}};

  tlv8Encoder_->set_map(messageMap);
  tlv8Encoder_->encode();

  return 1;
}

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

  send(clientID_, header, header_len, 0);
  send(clientID_, tlv, sizeof(tlv), 0);

  return 1;
}

int RTSPParser::get_cseq() {
  const char *cseq = strstr(msg_, "CSeq:");

  if (!cseq)
    return -1;

  sscanf(cseq, "CSeq: %d", &CSeq_);
  return 1;
}

int RTSPParser::get_content_length() {
  const char *len = strstr(msg_, "Content-Length:");

  if (!len)
    return -1;

  sscanf(len, "Content-Length: %d", &contentLength_);

  return 1;
}

int RTSPParser::get_title() {
  const char *lineEnd = strstr(msg_, "\r\n");
  if (!lineEnd)
    return -1;

  title_ = std::string((const char *)msg_, lineEnd);
  return 1;
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
        recv(clientID_, bodyBuffer_ + bodyRead, remaining, MSG_WAITALL);
    bodyBuffer_[contentLength_] = '\0';
    body_ = bodyBuffer_;

    remaining -= receivedSize;

    free(bodyBuffer_);
  } else if (remaining > 0) {
    int receivedSize =
        recv(clientID_, body_ + bodyRead, remaining, MSG_WAITALL);
    remaining -= receivedSize;
    bodyRead += receivedSize;
  }
  return 1;
}

std::unique_ptr<RTSPParser>
create_rtsp_parser(int clientID, std::string macAddress, std::string pi,
                   std::shared_ptr<FeatureFlags> featureFlags,
                   std::shared_ptr<StatusFlags> statusFlags) {
  return std::make_unique<RTSPParser>(clientID, macAddress, pi, featureFlags,
                                      statusFlags);
}
