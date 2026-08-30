#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class HAPCrypto {
public:
  HAPCrypto(std::vector<uint8_t>);
  ~HAPCrypto();

  int hkdf_sha512(const std::string &salt, const std::string &info);

  std::vector<uint8_t>
  chacha_decrypt(const std::vector<uint8_t> &ciphertextWithTag);

  int set_nonce(std::string label);

private:
  std::vector<uint8_t> sk_;
  std::vector<uint8_t> key_;
  std::vector<uint8_t> nonce_;
};
std::unique_ptr<HAPCrypto> create_hap_handler(std::vector<uint8_t> sk);
