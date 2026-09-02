#pragma once

#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <vector>

class CryptoHandler {
public:
  CryptoHandler();
  ~CryptoHandler();

  int store_retrieve_pkey();

  int set_accessory_x(std::vector<uint8_t> a);
  int set_signature();

  std::string get_public_hex_string();
  std::vector<uint8_t> get_public_key();
  std::vector<uint8_t> get_signature();

private:
  std::vector<uint8_t> identifier_, priv_, pub_, signature_, accessoryX_;
  EVP_PKEY *pkey_;
  EVP_PKEY_CTX *ctx_;
  std::string priv_key_hex_, pub_key_hex_;

  EVP_PKEY *generate_identity_keypair();
  int get_raw_keypair(EVP_PKEY *pkey);
};

std::shared_ptr<CryptoHandler> create_crypto_handler();
