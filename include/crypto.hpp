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
  std::string get_public_hex_string();
  std::vector<uint8_t> get_public_key();

private:
  EVP_PKEY *generate_identity_keypair();
  int get_raw_keypair(EVP_PKEY *pkey);

  std::vector<uint8_t> priv_, pub_;
  EVP_PKEY *pkey_;
  EVP_PKEY_CTX *ctx_;
  std::string priv_key_hex_, pub_key_hex_;
};

std::shared_ptr<CryptoHandler> create_crypto_handler();
