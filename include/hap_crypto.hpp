#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class HAPCrypto {
public:
  HAPCrypto(std::vector<uint8_t>);
  ~HAPCrypto() = default;

  int hkdf_sha512(const std::string &salt, const std::string &info);

  void set_cipher_tag(const std::vector<uint8_t> encryptedData);

  std::vector<uint8_t> chacha_decrypt();

  int set_nonce(std::string label);
  int M5_verification(std::vector<uint8_t> identifier,
                      std::vector<uint8_t> ltpk,
                      std::vector<uint8_t> signature);

private:
  std::vector<uint8_t> sk_, key_, nonce_, cipherText_, authTag_;
  size_t cipherLen_;
};
std::unique_ptr<HAPCrypto> create_hap_handler(std::vector<uint8_t> sk);
