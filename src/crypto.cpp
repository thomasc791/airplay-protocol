#include "crypto.hpp"
#include "utils.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <string>

namespace fs = std::filesystem;

CryptoHandler::CryptoHandler() { store_retrieve_pkey(); }
CryptoHandler::~CryptoHandler() {}

EVP_PKEY *CryptoHandler::generate_identity_keypair() {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  EVP_PKEY *pkey = nullptr;

  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_keygen(ctx, &pkey);

  EVP_PKEY_CTX_free(ctx);

  return pkey;
}

int CryptoHandler::get_raw_keypair(EVP_PKEY *pkey) {
  size_t priv_len = 32;
  size_t pub_len = 32;

  EVP_PKEY_get_raw_private_key(pkey, priv_, &priv_len);
  EVP_PKEY_get_raw_public_key(pkey, pub_, &pub_len);

  return 0;
}

int CryptoHandler::store_retrieve_pkey() {
  const char *xdg_data = std::getenv("XDG_DATA_HOME");
  fs::path baseDir =
      xdg_data ? fs::path(xdg_data) : fs::path(std::getenv("HOME"));
  fs::path keyDir = baseDir / "airplay-protocol";
  fs::path filePath = keyDir / "identity";

  if (!fs::exists(keyDir)) {
    if (!fs::create_directory(keyDir)) {
      std::cerr << "Failed to create directory at " << keyDir << std::endl;

      return -1;
    }
  }

  if (!fs::exists(filePath)) {

    pkey = generate_identity_keypair();
    get_raw_keypair(pkey);

    pk_string_ = chars_to_string(priv_, 32);

    std::ofstream keyFile(filePath);
    if (keyFile.is_open()) {
      keyFile << pk_string_;
    }

    EVP_PKEY_free(pkey);

    keyFile.close();

    return 0;
  } else {
    std::ifstream keyFile(filePath);
    std::getline(keyFile, pk_string_);

    keyFile.close();
  }

  return 0;
}

std::string CryptoHandler::get_pk_string() { return this->pk_string_; }

std::shared_ptr<CryptoHandler> create_crypto_handler() {
  return std::make_shared<CryptoHandler>();
}
