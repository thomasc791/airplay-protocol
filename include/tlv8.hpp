#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

enum TLV8Type_t : uint8_t {
  TLV8_METHOD = 0x00,
  TLV8_IDENTIFIER = 0x01,
  TLV8_SALT = 0x02,
  TLV8_PK = 0x03,
  TLV8_PROOF = 0x04,
  TLV8_ENCRYPTED_DATA = 0x05,
  TLV8_STATE = 0x06,
  TLV8_ERROR = 0x07,
  TLV8_SIGNATURE = 0x0a
};

class TLV8Decoder {
public:
  TLV8Decoder();
  ~TLV8Decoder();

  void reinterpret_message(const char *body, size_t len);
  void set_sub_message(std::vector<uint8_t> sm);
  void decode();
  void decode_sub();
  std::vector<uint8_t> read_message(const TLV8Type_t type);
  std::vector<uint8_t> read_sub_message(const TLV8Type_t type);

private:
  std::vector<uint8_t> message_;
  std::vector<uint8_t> subMessage_;
  std::vector<uint8_t> decodedMessage_;
  std::vector<uint8_t> body_;
  uint8_t len_;
  size_t curr_;
  bool longMessage_;
  TLV8Type_t type_;
  std::map<TLV8Type_t, std::vector<uint8_t>> messageDictionary_;
  std::map<TLV8Type_t, std::vector<uint8_t>> subMessageDictionary_;

  void reset();
  std::vector<uint8_t> read(const std::vector<uint8_t> m, size_t length);
  uint8_t read(const std::vector<uint8_t> m);
};

class TLV8Encoder {
public:
  TLV8Encoder();
  ~TLV8Encoder();

  int set_map(std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> map);
  int encode();
  std::vector<uint8_t> get_body();

private:
  std::vector<uint8_t> body_;
  size_t curr_;
  std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> messageMap_;

  void reset();
  int input_long_message(uint8_t type, std::vector<uint8_t> message);
  int input_short_message(uint8_t type, std::vector<uint8_t> message);
};

std::unique_ptr<TLV8Decoder> create_tlv8_decoder();
std::unique_ptr<TLV8Encoder> create_tlv8_encoder();
