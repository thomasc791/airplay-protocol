#include "crypto.hpp"
#include "airplay_server.hpp"
#include "utils.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

CryptoHandler::CryptoHandler() : priv_(32), pub_(32), pkey_(nullptr) {
  ctx_ = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  identifier_ = hex_to_chars(remove_colon(get_system_mac_address()));

  store_retrieve_pkey();
}
CryptoHandler::~CryptoHandler() {
  EVP_PKEY_free(pkey_);
  EVP_PKEY_CTX_free(ctx_);
}

EVP_PKEY *CryptoHandler::generate_identity_keypair() {
  pkey_ = nullptr;

  if (!EVP_PKEY_keygen_init(ctx_)) {
    throw std::runtime_error("EVP_PKEY key generation initialisation failed.");
  }

  if (!EVP_PKEY_keygen(ctx_, &pkey_)) {
    throw std::runtime_error("EVP_PKEY key generation failed.");
  }

  return pkey_;
}

int CryptoHandler::get_raw_keypair(EVP_PKEY *pkey) {
  size_t priv_len = 32;
  size_t pub_len = 32;

  if (priv_.size() != 32) {
    std::cerr << "EVP_PKEY key generation initialisation failed." << std::endl;
    return -1;
  }

  EVP_PKEY_get_raw_private_key(pkey, priv_.data(), &priv_len);
  EVP_PKEY_get_raw_public_key(pkey, pub_.data(), &pub_len);

  return 0;
}

int CryptoHandler::store_retrieve_pkey() {
  const char *xdg_data = std::getenv("XDG_DATA_HOME");
  fs::path baseDir =
      xdg_data ? fs::path(xdg_data) : fs::path(std::getenv("HOME"));
  fs::path keyDir = baseDir / "airplay-protocol";
  fs::path filePath = keyDir / "identity";

  fs::path pubPath = filePath;
  fs::path privPath = filePath;
  pubPath += ".pub";
  privPath += ".priv";

  if (!fs::exists(keyDir)) {
    if (!fs::create_directory(keyDir)) {
      std::cerr << "Failed to create directory at " << keyDir << std::endl;

      return -1;
    }
  }

  if (!fs::exists(pubPath)) {
    generate_identity_keypair();
    get_raw_keypair(pkey_);

    pub_key_hex_ = chars_to_hex(pub_);
    priv_key_hex_ = chars_to_hex(priv_);

    std::ofstream publicKeyFile(pubPath);
    if (publicKeyFile.is_open()) {
      publicKeyFile << pub_key_hex_;
    } else {
      std::cerr << "Error writing public key" << std::endl;
    }

    std::ofstream privateKeyFile(privPath);
    if (privateKeyFile.is_open()) {
      privateKeyFile << priv_key_hex_;
    } else {
      std::cerr << "Error writing private key" << std::endl;
    }

    publicKeyFile.close();

    return 0;
  } else {
    std::ifstream publicKeyFile(pubPath);
    std::ifstream privateKeyFile(privPath);
    std::getline(publicKeyFile, pub_key_hex_);
    std::getline(privateKeyFile, priv_key_hex_);

    priv_ = hex_to_chars(priv_key_hex_);
    pub_ = hex_to_chars(pub_key_hex_);

    pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                         priv_.data(), priv_.size());

    publicKeyFile.close();
    privateKeyFile.close();
  }

  return 0;
}

int CryptoHandler::set_accessory_x(std::vector<uint8_t> a) {
  if (a.size() != 32) {
    std::cerr << "Error setting accessory" << std::endl;
    return -1;
  }
  accessoryX_ = a;

  return 1;
}

int CryptoHandler::set_signature() {
  std::vector<uint8_t> messageInfo;
  messageInfo.insert(messageInfo.end(), identifier_.begin(), identifier_.end());
  messageInfo.insert(messageInfo.end(), accessoryX_.begin(), accessoryX_.end());
  messageInfo.insert(messageInfo.end(), pub_.begin(), pub_.end());

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey_) != 1) {
    std::cerr << "Error initialising signing" << std::endl;
    return -1;
  }

  size_t sigLen = 64;
  signature_ = std::vector<uint8_t>(sigLen);

  if (EVP_DigestSign(mdctx, signature_.data(), &sigLen, messageInfo.data(),
                     messageInfo.size()) != 1) {
    std::cerr << "Error signing signature" << std::endl;
    return -1;
  }

  EVP_MD_CTX_free(mdctx);

  return 1;
}

std::string CryptoHandler::get_public_hex_string() { return pub_key_hex_; }
std::vector<uint8_t> CryptoHandler::get_public_key() { return pub_; }
std::vector<uint8_t> CryptoHandler::get_signature() { return signature_; }

std::shared_ptr<CryptoHandler> create_crypto_handler() {
  return std::make_shared<CryptoHandler>();
}
