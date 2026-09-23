#include "rtsp.hpp"

#include "audio_control.hpp"
#include "audio_stream.hpp"
#include "crypto.hpp"
#include "pairing_manager.hpp"
#include "plist_decoder.hpp"
#include "plist_encoder.hpp"
#include "srp.hpp"
#include "tlv8.hpp"
#include "utils.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <iostream>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <sys/socket.h>
#include <utility>
#include <vector>

constexpr std::string tag = "SessionHandler";

SessionHandler::SessionHandler(int client_fd, std::string macAddress,
                               std::string pi,
                               std::shared_ptr<FeatureFlags> featureFlags,
                               std::shared_ptr<StatusFlags> statusFlags,
                               std::shared_ptr<PairingManager> pairingManager)
    : running_{true}, clientID_(client_fd), contentLength_(), CSeq_(),
      bodyBuffer_(nullptr), msg_(nullptr), macAddress_(macAddress), pi_(pi),
      header_{}, featureFlags_(featureFlags), statusFlags_(statusFlags),
      pairingManager_(pairingManager) {
  std::cout << "Created RTSP parser, listening to client with ID: " << client_fd
            << std::endl;

  plistEncoder_ = create_plist_encoder();
  plistDecoder_ = create_plist_decoder();
  tlv8Decoder_ = create_tlv8_decoder();
  tlv8Encoder_ = create_tlv8_encoder();
  cryptoHandler_ = create_crypto_handler();
  srpHandler_ = create_srp_handler();
}

SessionHandler::~SessionHandler() {
  free(bodyBuffer_);
  plistEncoder_.reset();
  plistDecoder_.reset();
  srpHandler_.reset();
  cryptoHandler_.reset();
  featureFlags_.reset();
  statusFlags_.reset();
  tlv8Decoder_.reset();
  tlv8Encoder_.reset();
  pairingManager_.reset();
  fairPlayWrapper_.reset();
  ptpHandler_.reset();
  eventHandler_.reset();
  audioDataHandler_.reset();
  audioControlHandler_.reset();

  log_event(tag, "Deleting handler.");
}

int SessionHandler::set_client(int currentClient) {
  clientID_ = currentClient;
  return 1;
}

int SessionHandler::set_msg(char *tcpMessage, int len) {
  // ESP_LOGI(TAG, "Set message with length: %d", len);
  msg_ = tcpMessage;
  messageLength_ = len;
  return 1;
}

int SessionHandler::parse_message() {
  msg_[messageLength_] = '\0';

  reset_state();

  get_content_length();
  get_cseq();
  get_req();
  get_req_type();
  get_title();
  get_body();

  std::cout << request_ << std::endl;

  if ("/info RTSP/1.0" == title_) {
    rtsp_get_info();
  } else if ("/pair-setup RTSP/1.0" == title_) {
    std::cout << "/pair-setup" << std::endl;
    rtsp_post_pair_setup();
  } else if ("/pair-verify RTSP/1.0" == title_) {
    std::cout << "/pair-verify" << std::endl;
    rtsp_post_pair_verify();
  } else if ("/fp-setup RTSP/1.0" == title_) {
    std::cout << "/fp-setup" << std::endl;
    rtsp_post_fp_setup();
  } else if ("/feedback RTSP/1.0" == title_) {
    std::cout << "/feedback" << std::endl;
    rtsp_post_feedback();
  } else if ("/command RTSP/1.0" == title_) {
    std::cout << "/command" << std::endl;
    rtsp_post_commands();
  } else if ("/audioMode RTSP/1.0" == title_) {
    std::cout << "/audioMode" << std::endl;
    rtsp_post_audiomode();
  } else if ("SETUP" == requestType_) {
    std::cout << "SETUP" << std::endl;
    rtsp_setup();
  } else if ("TEARDOWN" == requestType_) {
    std::cout << "TEARDOWN" << std::endl;
    rtsp_teardown();
  } else if ("RECORD" == requestType_) {
    std::cout << "RECORD" << std::endl;
    rtsp_record();
  } else if ("GET_PARAMETER" == requestType_) {
    std::cout << "GET_PARAMETER" << std::endl;
    rtsp_get_parameter();
  } else if ("SET_PARAMETER" == requestType_) {
    std::cout << "SET_PARAMETER" << std::endl;
    rtsp_get_parameter();
  } else if ("SETPEERS" == requestType_) {
    std::cout << "SETPEERS" << std::endl;
    rtsp_set_peers();
  } else if ("SETRATEANCHORTIME" == requestType_) {
    std::cout << "SETRATEANCHORTIME" << std::endl;
    rtsp_set_rate_anchortime();
  } else {
    std::cout << msg_ << std::endl;
    std::cout << "[RTSPParser] Unknown or encrypted message received! Lengte: "
              << messageLength_ << std::endl;
    std::cout << "Ruwe hex data:" << std::endl;
    for (int i = 0; i < messageLength_; i++) {
      printf("%02x ", (unsigned char)msg_[i]);
    }
    printf("\n");

    rtsp_empty_message();
  }
  printf("\n");
  messageLength_ = 0;
  return 1;
}

std::tuple<std::string, u8Vec_t> SessionHandler::get_response() {
  return {sendHeader_, sendBody_};
}

int SessionHandler::reset_state() {
  CSeq_ = -1;
  contentLength_ = -1;

  return 1;
}

u8Vec_t SessionHandler::create_plist() {
  using V = PlistEncoder::Value;

  auto plist = plistEncoder_->serialize(V::dict({
      {"deviceID", V::string(macAddress_)},
      {"features", V::uint(featureFlags_->get_raw())},
      {"model", V::string("AudioAccessory6,1")},
      {"gcgl", V::string("0")},
      {"nameIsFactoryDefault", V::boolean(false)},
      {"pi", V::string(pi_)},
      {"pk", V::data(cryptoHandler_->get_public_key())},
      {"protocolVersion", V::string("1.1")},
      {"password", V::boolean(true)},
      {"sourceVersion", V::string("366.0")},
      {"statusFlags", V::uint(statusFlags_->get_raw())},
      // {"audioFormats", V::array({V::dict({
      //                      {"type", V::uint(96)},
      //                      {"audioInputFormats", V::uint(0x01000000)},
      //                      {"audioOutputFormats", V::uint(0x01000000)},
      // })})},
  }));
  return plist;
}

int SessionHandler::rtsp_get_info() {
  u8Vec_t plist = create_plist();

  int header_len =
      create_header("application/x-apple-binary-plist", plist.size());

  sendHeader_ = header_;
  sendHeaderLen_ = header_len;
  sendBody_ = plist;

  return 1;
}

int SessionHandler::rtsp_post_pair_setup() {
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

  u8Vec_t body;
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

  int header_len = create_header("application/octet-stream", body.size());

  std::cout << "Sending state: " << std::hex << currentState + 1 << std::endl;

  sendHeader_ = header_;
  sendHeaderLen_ = header_len;
  sendBody_ = body;

  if (err <= 0) {
    std::cerr << "Could not send message." << std::endl;
    return -1;
  }

  return 1;
};

int SessionHandler::pair_setup_m2() {
  std::vector<std::pair<TLV8Type_t, u8Vec_t>> messageMap = {
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

int SessionHandler::pair_setup_m4() {
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

  std::vector<std::pair<TLV8Type_t, u8Vec_t>> messageMap = {
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

int SessionHandler::pair_setup_m5() {
  int err;
  u8Vec_t hkdfKey =
      hkdf_sha512("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info",
                  cryptoHandler_->get_shared_key());
  if (hkdfKey.size() != 32)
    err = -1;

  cryptoHandler_->set_encrypt_key(hkdfKey);

  err = cryptoHandler_->set_nonce("PS-Msg05");

  auto [cipher, tag] =
      get_cipher_tag(tlv8Decoder_->read_message(TLV8_ENCRYPTED_DATA));
  u8Vec_t blob =
      cryptoHandler_->chacha_decrypt(cipher, cryptoHandler_->get_nonce(), tag);

  tlv8Decoder_->set_sub_message(blob);
  tlv8Decoder_->decode_sub();

  hkdfKey = hkdf_sha512("Pair-Setup-Controller-Sign-Salt",
                        "Pair-Setup-Controller-Sign-Info",
                        cryptoHandler_->get_shared_key());

  u8Vec_t messageInfo;
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

  pairingManager_->add_paired_device({
      tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER),
      tlv8Decoder_->read_sub_message(TLV8_PK),
  });

  return err;
}

int SessionHandler::pair_setup_m6() {
  int err;
  auto hkdfKey = hkdf_sha512("Pair-Setup-Accessory-Sign-Salt",
                             "Pair-Setup-Accessory-Sign-Info",
                             cryptoHandler_->get_shared_key());
  if (hkdfKey.size() != 32)
    err = -1;

  err = cryptoHandler_->set_accessory_x(hkdfKey);
  err = cryptoHandler_->set_signature(cryptoHandler_->get_accessory_x(),
                                      cryptoHandler_->get_identifier(),
                                      cryptoHandler_->get_public_key());

  std::vector<std::pair<TLV8Type_t, u8Vec_t>> subMessageMap = {
      {TLV8_IDENTIFIER, cryptoHandler_->get_identifier()},
      {TLV8_PK, cryptoHandler_->get_public_key()},
      {TLV8_SIGNATURE, cryptoHandler_->get_signature()},
  };

  tlv8Encoder_->set_map(subMessageMap);
  tlv8Encoder_->encode();

  err = cryptoHandler_->set_nonce("PS-Msg06");

  auto subEncryptedSubmessage =
      cryptoHandler_->chacha_encrypt(tlv8Encoder_->get_body());

  std::vector<std::pair<TLV8Type_t, u8Vec_t>> messageMap = {
      {TLV8_STATE, {0x06}},
      {TLV8_ENCRYPTED_DATA, subEncryptedSubmessage},
  };

  tlv8Encoder_->set_map(messageMap);
  tlv8Encoder_->encode();

  return err;
}

int SessionHandler::rtsp_post_pair_verify() {
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

  u8Vec_t body;
  uint8_t currentState = tlv8Decoder_->read_message(TLV8_STATE)[0];

  printf("Method: %02x\n", currentState);

  switch (currentState) {

  case 0x01:

    // rtsp_post_pair_error();
    err = pair_verify_m2();
    if (err <= 0)
      std::cout << "Error generating Pair-Verify M2" << std::endl;

    break;
  case 0x03:
    err = pair_verify_m3();
    if (err <= 0) {
      std::cerr << "Error during verification of M3 message" << std::endl;
      break;
    }

    err = pair_verify_m4();

    verified_ = true;
    break;
  }

  if (err <= 0) {
    std::cout << "Encountered Error, sending error message" << std::endl;
    rtsp_post_pair_error();
    return 0;
  }

  body = tlv8Encoder_->get_body();

  int header_len = create_header("application/octet-stream", body.size());

  std::cout << "Sending state: " << std::hex << currentState + 1 << std::endl;

  sendHeaderLen_ = header_len;
  sendHeader_ = header_;
  sendBody_ = body;

  if (err <= 0) {
    std::cerr << "Could not send message." << std::endl;
    return -1;
  }

  return 1;
};

int SessionHandler::pair_verify_m2() {
  cryptoHandler_->generate_ephemeral_key();
  cryptoHandler_->set_client_ephemeral_pub(tlv8Decoder_->read_message(TLV8_PK));
  cryptoHandler_->calculate_shared_key();

  cryptoHandler_->set_signature(cryptoHandler_->get_ephemeral_key(),
                                cryptoHandler_->get_identifier(),
                                cryptoHandler_->get_client_ephemeral_key());

  cryptoHandler_->set_encrypt_key(cryptoHandler_->get_shared_key());

  auto hkdfKey =
      hkdf_sha512("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info",
                  cryptoHandler_->get_shared_key());

  cryptoHandler_->set_encrypt_key(hkdfKey);

  std::vector<std::pair<TLV8Type_t, u8Vec_t>> subMessageMap = {
      {TLV8_IDENTIFIER, cryptoHandler_->get_identifier()},
      {TLV8_SIGNATURE, cryptoHandler_->get_signature()},
  };

  tlv8Encoder_->set_map(subMessageMap);
  tlv8Encoder_->encode();

  cryptoHandler_->set_nonce("PV-Msg02");

  auto encryptedSubMessage =
      cryptoHandler_->chacha_encrypt(tlv8Encoder_->get_body());

  std::vector<std::pair<TLV8Type_t, u8Vec_t>> messageMap = {
      {TLV8_STATE, {0x02}},
      {TLV8_PK, cryptoHandler_->get_ephemeral_key()},
      {TLV8_ENCRYPTED_DATA, encryptedSubMessage},
  };

  tlv8Encoder_->set_map(messageMap);
  tlv8Encoder_->encode();

  return 1;
}

int SessionHandler::pair_verify_m3() {
  int err = cryptoHandler_->set_nonce("PV-Msg03");
  auto [cipher, tag] =
      get_cipher_tag(tlv8Decoder_->read_message(TLV8_ENCRYPTED_DATA));

  auto decryptBlob =
      cryptoHandler_->chacha_decrypt(cipher, cryptoHandler_->get_nonce(), tag);
  tlv8Decoder_->set_sub_message(decryptBlob);
  tlv8Decoder_->decode_sub();

  auto [exists, pubKey] = pairingManager_->get_device_key(
      tlv8Decoder_->read_sub_message(TLV8_IDENTIFIER));

  if (!exists) {
    std::cerr << "Connecting device does not exist yet. Returning error."
              << std::endl;
    return -1;
  }

  u8Vec_t messageInfo;
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

int SessionHandler::pair_verify_m4() {
  std::vector<std::pair<TLV8Type_t, u8Vec_t>> messageMap = {
      {TLV8_STATE, {0x04}}};

  tlv8Encoder_->set_map(messageMap);
  tlv8Encoder_->encode();

  return 1;
}

int SessionHandler::rtsp_post_fp_setup() {
  if (!fairPlayWrapper_)
    fairPlayWrapper_ = create_fp_wrapper();

  u8Vec_t fpBody(reinterpret_cast<const uint8_t *>(body_),
                 reinterpret_cast<const uint8_t *>(body_) + contentLength_);

  u8Vec_t body;
  u8Vec_t vecBody(reinterpret_cast<const char *>(body_) + 4,
                  reinterpret_cast<const char *>(body_) + contentLength_);

  auto fpVersion = vecBody[0];
  if (0x03 != fpVersion) {
    return 0;
  }

  auto fpState = vecBody[2];
  auto fpMode = vecBody[10];

  switch (fpState) {
  case (0x01):
    fairPlayWrapper_->set_mode(fpMode);
    body = fp3_setup_m2();
    break;
  case (0x03):
    fp3_setup_m3();
    body = fp3_setup_m4();
    break;
  }

  int header_len = create_header("application/octet-stream", body.size());

  sendHeaderLen_ = header_len;
  sendHeader_ = header_;
  sendBody_ = body;

  return 1;
}

int SessionHandler::rtsp_setup() {
  u8Vec_t body;

  std::cout << "Decoding RTSP Setup BPlist" << std::endl;
  auto dictionary = plistDecoder_->decode(body_, contentLength_).dictVal;

  if (!plistDecoder_->has_key(dictionary, "streams")) {
    body = rtsp_setup_m1(dictionary);
  } else {
    body = rtsp_setup_media_stream(dictionary);
  }

  int header_len =
      create_header("application/x-apple-binary-plist", body.size());

  sendHeaderLen_ = header_len;
  sendHeader_ = header_;
  sendBody_ = body;

  return 1;
}

u8Vec_t SessionHandler::rtsp_setup_m1(pwVal::Dict dictionary) {
  using V = PlistEncoder::Value;

  ptpHandler_ = create_ptp_timing_handler();
  eventHandler_ = create_event_handler();

  ptpHandler_->start();
  eventHandler_->start();

  std::vector<uint8_t> bplistPayload = plistEncoder_->serialize(
      V::dict({{"timingPort", pwVal::uint(ptpHandler_->get_port())},
               {"eventPort", pwVal::uint(eventHandler_->get_port())}}));

  return bplistPayload;
}

u8Vec_t SessionHandler::rtsp_setup_media_stream(pwVal::Dict dictionary) {
  using V = PlistEncoder::Value;
  u8Vec_t body = {};

  auto streams = plistDecoder_->get(dictionary, "streams");

  auto streamType =
      plistDecoder_->get(streams.arrayVal[0].dictVal, "type").uintVal;

  std::cout << "Stream type: " << streamType << std::endl;

  if (streamType == 130) {
    body = rtsp_setup_m2(dictionary);
  } else if (streamType == 96 || plistDecoder_->has_key(dictionary, "ekey")) {
    body = rtsp_setup_m2(dictionary);
  } else if (streamType == 103 || plistDecoder_->has_key(dictionary, "shk")) {

    audioDataHandler_ = create_audio_handler();
    audioDataHandler_->start();

    audioControlHandler_ = create_audio_control_handler();
    audioControlHandler_->start();

    pwVal::Dict streamDict(
        {{"type", pwVal::uint(103)},
         {"dataPort", pwVal::uint(audioDataHandler_->get_port())},
         {"audioBufferSize", pwVal::uint(0x800000)},
         {"streamID", pwVal::uint(0x000001)},
         {"controlPort", pwVal::uint(audioControlHandler_->get_port())}});

    pwVal::Array streamsArray;
    streamsArray.push_back(pwVal::dict(streamDict));

    pwVal::Dict rootDict;
    rootDict.push_back({"streams", pwVal::array(streamsArray)});

    body = plistEncoder_->serialize(pwVal::dict(rootDict));
  }

  return body;
}

u8Vec_t SessionHandler::rtsp_setup_m2(pwVal::Dict dictionary) {

  audioControlHandler_ = create_audio_control_handler();
  audioControlHandler_->start();

  pwVal::Dict streamDict;

  streamDict.push_back({"type", pwVal::uint(130)});
  streamDict.push_back(
      {"dataPort", pwVal::uint(audioControlHandler_->get_port())});

  pwVal::Array streamsArray;
  streamsArray.push_back(pwVal::dict(streamDict));

  pwVal::Dict rootDict;
  rootDict.push_back({"streams", pwVal::array(streamsArray)});

  return plistEncoder_->serialize(pwVal::dict(rootDict));
}

u8Vec_t SessionHandler::rtsp_setup_m3(pwVal::Dict dictionary) {
  using V = PlistEncoder::Value;

  std::vector<uint8_t> bplistPayload = plistEncoder_->serialize(
      V::dict({{"timingPort", pwVal::uint(ptpHandler_->get_port())},
               {"eventPort", pwVal::uint(eventHandler_->get_port())}}));

  return bplistPayload;
}

int SessionHandler::rtsp_record() {
  u8Vec_t body = {};

  int header_len = snprintf(header_, sizeof(header_),
                            "RTSP/1.0 200 OK\r\n"
                            "CSeq: %d\r\n"
                            "Audio-Latency: 0\r\n"
                            "Server: AirTunes/366.0\r\n"
                            "Content-Length: 0\r\n\r\n",
                            CSeq_);

  sendHeaderLen_ = header_len;
  sendHeader_ = header_;
  sendBody_ = body;

  return 1;
}

int SessionHandler::rtsp_post_feedback() { return rtsp_empty_message(); }
int SessionHandler::rtsp_post_audiomode() { return rtsp_empty_message(); }
int SessionHandler::rtsp_set_peers() { return rtsp_empty_message(); }
int SessionHandler::rtsp_set_rate_anchortime() { return rtsp_empty_message(); }

int SessionHandler::rtsp_teardown() {
  rtsp_empty_message();
  running_ = false;

  return 1;
}

int SessionHandler::rtsp_post_commands() { return rtsp_empty_message(); }

int SessionHandler::rtsp_get_parameter() {
  std::string volume = "volume: 0.000000\r\n";
  u8Vec_t body(volume.begin(), volume.end());

  int header_len = create_header("text/parameters", body.size());

  sendHeaderLen_ = header_len;
  sendHeader_ = header_;
  sendBody_ = body;

  return 1;
}

int SessionHandler::rtsp_empty_message() {
  u8Vec_t body = {};

  int header_len = create_header();

  sendHeaderLen_ = header_len;
  sendHeader_ = header_;
  sendBody_ = body;

  return 1;
}

u8Vec_t SessionHandler::fp3_setup_m2() {
  return fairPlayWrapper_->get_reply_message();
}

u8Vec_t SessionHandler::fp3_setup_m3() {
  fairPlayWrapper_->set_key_msg(body_);

  return {};
}

u8Vec_t SessionHandler::fp3_setup_m4() {
  u8Vec_t body;
  auto fpReplyHeader = fairPlayWrapper_->get_reply_header();
  body.insert(body.begin(), fpReplyHeader.begin(), fpReplyHeader.end());
  body.insert(body.begin() + 12, &body_[144], &body_[164]);

  return body;
}

int SessionHandler::rtsp_post_pair_error() {
  u8Vec_t tlv = {0x06, 0x01, 0x02,  // State = M2
                 0x07, 0x01, 0x02}; // Error = Authentication

  int header_len = create_header("application/octet-stream", sizeof(tlv));

  sendHeader_ = header_;
  sendHeaderLen_ = header_len;
  sendBody_ = tlv;

  return 1;
}

int SessionHandler::get_cseq() {
  const char *cseq = strstr(msg_, "CSeq:");

  if (!cseq)
    return -1;

  sscanf(cseq, "CSeq: %d", &CSeq_);
  return 1;
}

int SessionHandler::get_content_length() {
  const char *len = strstr(msg_, "Content-Length:");

  if (!len)
    return -1;

  sscanf(len, "Content-Length: %d", &contentLength_);

  return 1;
}

int SessionHandler::get_req() {
  const char *request = strstr(msg_, "\r\n");
  if (!request)
    return -1;

  request_ = std::string((const char *)msg_, request);

  return 1;
}

int SessionHandler::get_req_type() {
  std::string::size_type n = request_.find(" ");
  if (std::string::npos == n)
    return -1;

  requestType_ = std::string(request_.begin(), request_.begin() + n);
  return 1;
}

int SessionHandler::get_title() {
  std::string::size_type n = request_.find("/");
  if (std::string::npos == n)
    return -1;

  title_ = std::string(request_.begin() + n, request_.end());
  return 1;
}

int SessionHandler::get_body() {
  body_ = strstr(msg_, "\r\n\r\n");
  if (!body_)
    return -1;
  body_ += 4;

  size_t headerLength = body_ - msg_;
  int bodyRead = messageLength_ - headerLength;
  int remaining = contentLength_ - bodyRead;

  std::string msgHeader(msg_, headerLength);

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
  } else if (remaining > 0) {
    int receivedSize =
        recv(clientID_, body_ + bodyRead, remaining, MSG_WAITALL);
    remaining -= receivedSize;
    bodyRead += receivedSize;
  }
  return 1;
}

u8Vec_t SessionHandler::get_shared_key() {
  return cryptoHandler_->get_shared_key();
}

int SessionHandler::create_header(std::string applicationType,
                                  size_t plistSize) {
  return snprintf(header_, sizeof(header_),
                  "RTSP/1.0 200 OK\r\n"
                  "CSeq: %d\r\n"
                  "Server: AirTunes/366.0\r\n"
                  "Content-Type: %s\r\n"
                  "Content-Length: %d\r\n"
                  "\r\n",
                  CSeq_, applicationType.c_str(), (int)plistSize);
}

int SessionHandler::create_header() {
  return snprintf(header_, sizeof(header_),
                  "RTSP/1.0 200 OK\r\n"
                  "CSeq: %d\r\n"
                  "Server: AirTunes/366.0\r\n"
                  "Content-Length: 0\r\n"
                  "\r\n",
                  CSeq_);
}

std::shared_ptr<SessionHandler>
create_rtsp_parser(int clientID, std::string macAddress, std::string pi,
                   std::shared_ptr<FeatureFlags> featureFlags,
                   std::shared_ptr<StatusFlags> statusFlags,
                   std::shared_ptr<PairingManager> pairingManager) {
  return std::make_shared<SessionHandler>(
      clientID, macAddress, pi, featureFlags, statusFlags, pairingManager);
}
