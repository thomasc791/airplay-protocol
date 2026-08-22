#include "crypto.hpp"
#include "utils.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <string>

namespace fs = std::filesystem;

CryptoHandler::CryptoHandler() : pkey(nullptr) { store_retrieve_pkey(); }
CryptoHandler::~CryptoHandler() {}

EVP_PKEY *CryptoHandler::generate_identity_keypair() {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  EVP_PKEY *pkey = nullptr;

  if (!EVP_PKEY_keygen_init(ctx)) {
    std::cerr << "EVP_PKEY key generation initialisation failed." << std::endl;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    std::cerr << "EVP_PKEY key generation failed." << std::endl;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
  }

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

    pub_key_hex_ = chars_to_string(pub_, 32);
    priv_key_hex_ = chars_to_string(priv_, 32);

    std::ofstream publicKeyFile(filePath / ".pub");
    if (publicKeyFile.is_open()) {
      publicKeyFile << pub_key_hex_;
    }

    std::ofstream privateKeyFile(filePath / ".priv");
    if (privateKeyFile.is_open()) {
      privateKeyFile << priv_key_hex_;
    }

    EVP_PKEY_free(pkey);
    pkey = nullptr;

    publicKeyFile.close();

    return 0;
  } else {
    std::ifstream publicKeyFile(filePath / ".pub");
    std::ifstream privateKeyFile(filePath / ".priv");
    std::getline(publicKeyFile, pub_key_hex_);
    std::getline(privateKeyFile, priv_key_hex_);

    publicKeyFile.close();
    privateKeyFile.close();
  }

  return 0;
}

std::string CryptoHandler::get_public_hex_string() {
  return this->pub_key_hex_;
}

std::shared_ptr<CryptoHandler> create_crypto_handler() {
  return std::make_shared<CryptoHandler>();
}
