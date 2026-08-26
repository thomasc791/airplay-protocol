#include "tlv8.hpp"
#include <cstdio>
#include <iostream>
#include <memory>
#include <vector>

TLV8Decoder::TLV8Decoder() : curr_(0), messageDictionary_({}) { curr_ = 0; }
TLV8Decoder::~TLV8Decoder() {}

void TLV8Decoder::reinterpretMessage(const char *body, size_t len) {
  message_ =
      std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(body),
                           reinterpret_cast<const uint8_t *>(body) + len);
}

void TLV8Decoder::decode() {
  reset();

  while (curr_ < message_.size()) {
    body_.clear();

    type_ = TLV8Type(read());
    len_ = read();

    if (len_ == 0xff) {
      while (len_ == 0xff) {
        std::vector<uint8_t> readBody = read(255);
        body_.insert(body_.end(), readBody.begin(), readBody.end());
        if (type_ != TLV8Type(read())) {
          std::cerr << "Error continueing message." << std::endl;
          return;
        }

        if (curr_ >= message_.size())
          break;

        len_ = read();
      }

      std::vector<uint8_t> readBody = read(len_);
      body_.insert(body_.end(), readBody.begin(), readBody.end());
    } else if (len_ == 1) {
      body_ = {read()};
    } else {
      body_ = read(len_);
    }

    messageDictionary_[type_] = body_;
  }

  // switch (message_[curr_ - 1]) {
  // case 0x00:
  //   std::cout << "Method" << std::endl;
  //   break;
  // case 0x01:
  //   std::cout << "Identifier" << std::endl;
  //   break;
  // case 0x02:
  //   std::cout << "Salt" << std::endl;
  //   break;
  // case 0x03:
  //   std::cout << "PublicKey" << std::endl;
  //   break;
  // case 0x04:
  //   std::cout << "Proof" << std::endl;
  //   break;
  // case 0x05:
  //   std::cout << "EncryptedData" << std::endl;
  //   break;
  // case 0x06:
  //   std::cout << "State" << std::endl;
  //   break;
  // case 0x07:
  //   std::cout << "Error" << std::endl;
  //   break;
  // case 0x0a:
  //   std::cout << "Signature" << std::endl;
  //   break;
  // }

  return;
}

std::vector<uint8_t> TLV8Decoder::read(size_t length) {
  if (curr_ + length > message_.size()) {
    std::cerr << "Message shorter than wanted read length: " << curr_ + length
              << ", Message length: " << message_.size() << std::endl;
    return {};
  }

  std::vector<uint8_t> block(message_.begin() + curr_,
                             message_.begin() + curr_ + length);

  curr_ += length;
  return block;
}
uint8_t TLV8Decoder::read() {
  if (curr_ >= message_.size()) {
    std::cerr << "Reading beyond message not allowed" << std::endl;
    return 0x00;
  }

  uint8_t c = message_[curr_];
  curr_++;

  return c;
};

std::unique_ptr<TLV8Decoder> create_tlv8_decoder() {
  return std::make_unique<TLV8Decoder>();
}

void TLV8Decoder::reset() {
  curr_ = 0;
  body_.clear();
  messageDictionary_.clear();
}
