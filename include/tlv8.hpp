#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

enum TLV8Type : uint8_t {
  METHOD = 0x00,
  IDENTIFIER = 0x01,
  SALT = 0x02,
  PK = 0x03,
  PROOF = 0x04,
  ENCRYPTED_DATA = 0x05,
  STATE = 0x06,
  ERROR = 0x07,
  SIGNATURE = 0x0a
};

class TLV8Decoder {
public:
  TLV8Decoder();
  ~TLV8Decoder();

  void reinterpretMessage(const char *body, size_t len);
  void decode();

private:
  std::vector<uint8_t> message_;
  std::vector<uint8_t> decodedMessage_;
  std::vector<uint8_t> body_;
  uint8_t len_;
  size_t curr_;
  bool longMessage_;
  TLV8Type type_;
  std::map<TLV8Type, std::vector<uint8_t>> messageDictionary_;

  void reset();
  std::vector<uint8_t> read(size_t to);
  uint8_t read();
};

std::unique_ptr<TLV8Decoder> create_tlv8_decoder();
