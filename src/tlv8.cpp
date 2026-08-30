#include "tlv8.hpp"
#include <cstdio>
#include <iostream>
#include <memory>
#include <vector>

/* ==================================================
 * ================= TLV8 Decoder ===================
 * ================================================== */

TLV8Decoder::TLV8Decoder() : curr_(0), messageDictionary_({}) { curr_ = 0; }
TLV8Decoder::~TLV8Decoder() {}

void TLV8Decoder::reinterpret_message(const char *body, size_t len) {
  message_ =
      std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(body),
                           reinterpret_cast<const uint8_t *>(body) + len);
}

void TLV8Decoder::set_sub_message(std::vector<uint8_t> sm) { subMessage_ = sm; }

void TLV8Decoder::decode() {
  reset();

  while (curr_ < message_.size()) {
    body_.clear();

    type_ = TLV8Type_t(read());
    len_ = (size_t)read();

    if (len_ == 1) {
      body_ = {read()};
    } else {
      body_ = read((size_t)len_);
    }

    auto [_, success] = messageDictionary_.try_emplace(type_, body_);
    if (!success) {
      messageDictionary_[type_].insert(messageDictionary_[type_].end(),
                                       body_.begin(), body_.end());
    }
  }

  return;
}

void TLV8Decoder::decode_sub() {
  curr_ = 0;

  while (curr_ < subMessage_.size()) {
    body_.clear();

    type_ = TLV8Type_t(read());
    len_ = (size_t)read();

    if (len_ == 1) {
      body_ = {read()};
    } else {
      body_ = read((size_t)len_);
    }

    auto [_, success] = subMessageDictionary_.try_emplace(type_, body_);
    if (!success) {
      subMessageDictionary_[type_].insert(subMessageDictionary_[type_].end(),
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

std::vector<uint8_t> TLV8Decoder::read_message(const TLV8Type_t type) {
  return messageDictionary_[type];
}

void TLV8Decoder::reset() {
  curr_ = 0;
  body_.clear();
  messageDictionary_.clear();
  subMessage_.clear();
  subMessageDictionary_.clear();
}

/* ==================================================
 * ================= TLV8 Encoder ===================
 * ================================================== */

TLV8Encoder::TLV8Encoder() : curr_(0), messageMap_({}) {}
TLV8Encoder::~TLV8Encoder() {}

int TLV8Encoder::set_map(
    std::vector<std::pair<TLV8Type_t, std::vector<uint8_t>>> m) {
  if (m.empty()) {
    std::cerr << "Setting message map to empty map. Quitting." << std::endl;
    return -1;
  }

  messageMap_ = m;
  return 0;
}

int TLV8Encoder::encode() {
  if (messageMap_.empty()) {
    std::cerr << "Message map is empty. Quitting." << std::endl;
    return -1;
  }

  int err = 0;

  body_.clear();
  for (auto [k, v] : messageMap_) {
    if (v.size() <= 255) {
      err = input_short_message(k, v);
    } else {
      err = input_long_message(k, v);
    }
    if (err < 0) {
      std::cerr << "Error during message insertion. Quitting." << std::endl;
      return err;
    }
  }

  return err;
}

int TLV8Encoder::input_long_message(uint8_t type, std::vector<uint8_t> m) {
  if (m.size() <= 255) {
    std::cerr << "Message size to short. Quitting." << std::endl;
    return -1;
  }

  curr_ = 0;
  size_t numBlocks = m.size() / 255;

  for (size_t i = 0; i < numBlocks; i++) {
    body_.insert(body_.end(), type);
    body_.insert(body_.end(), 255);
    body_.insert(body_.end(), m.begin() + curr_, m.begin() + curr_ + 255);
    curr_ += 255;
  }

  body_.insert(body_.end(), type);
  body_.insert(body_.end(), m.size() % 255);

  if (m.size() % 255 != m.size() - curr_) {
    std::cerr << "Remainder not equal to calculated remainder. Quitting."
              << std::endl;
    return -1;
  }

  body_.insert(body_.end(), m.begin() + curr_, m.end());

  return 0;
}

int TLV8Encoder::input_short_message(uint8_t type,
                                     std::vector<uint8_t> message) {
  if (message.size() > 255) {
    std::cerr << "Message size to long. Quitting." << std::endl;
    return -1;
  }

  body_.insert(body_.end(), type);
  body_.insert(body_.end(), message.size());
  body_.insert(body_.end(), message.begin(), message.end());

  return 0;
}

std::vector<uint8_t> TLV8Encoder::get_body() { return body_; }

std::unique_ptr<TLV8Decoder> create_tlv8_decoder() {
  return std::make_unique<TLV8Decoder>();
}

std::unique_ptr<TLV8Encoder> create_tlv8_encoder() {
  return std::make_unique<TLV8Encoder>();
}
