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

    if (len_ == 1) {
      body_ = {read()};
    } else {
      body_ = read(len_);
    }

    auto [_, success] = messageDictionary_.emplace(type_, body_);
    if (!success) {
      messageDictionary_[type_].insert(messageDictionary_[type_].begin(),
                                       body_.begin(), body_.end());
    }
  }

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
