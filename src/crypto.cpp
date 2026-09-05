#include "crypto.hpp"
#include "airplay_server.hpp"
#include "utils.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

CryptoHandler::CryptoHandler()
    : priv_(32), pub_(32), pkey_(nullptr, EVP_PKEY_free),
      ephemeralPKey_(nullptr, EVP_PKEY_free), peerPkey_(nullptr, EVP_PKEY_free),
      ctx_(nullptr, EVP_PKEY_CTX_free),
      cipherCtx_(nullptr, EVP_CIPHER_CTX_free) {
  ctx_ = make_ctx(EVP_PKEY_ED25519);
  std::string mac = get_system_mac_address();
  std::cout << mac << std::endl;
  authTag_ = std::vector<uint8_t>(16);
  identifier_ = std::vector<uint8_t>(mac.begin(), mac.end());

  store_retrieve_pkey();
  generate_ephemeral_key();
}
CryptoHandler::~CryptoHandler() {}

int CryptoHandler::generate_identity_keypair() {
  EVP_PKEY *pkeyRaw = nullptr;

  if (!EVP_PKEY_keygen_init(ctx_.get())) {
    throw std::runtime_error("EVP_PKEY key generation initialisation failed.");
  }

  if (!EVP_PKEY_keygen(ctx_.get(), &pkeyRaw)) {
    EVP_PKEY_free(pkeyRaw);
    throw std::runtime_error("EVP_PKEY key generation failed.");
  }

  pkey_ = EvpPkPtr(pkeyRaw, EVP_PKEY_free);

  return 1;
}

int CryptoHandler::generate_ephemeral_key() {
  EVP_PKEY *ephRaw = nullptr;
  EvpCtxPtr ctx = make_ctx(EVP_PKEY_X25519);

  if (!EVP_PKEY_keygen_init(ctx.get())) {
    throw std::runtime_error(
        "EVP_PKEY Ephemeral key generation initialisation failed.");
  }

  if (!EVP_PKEY_keygen(ctx.get(), &ephRaw)) {
    EVP_PKEY_free(ephRaw);
    throw std::runtime_error("EVP_PKEY Ephemeral key generation failed.");
  }

  ephemeralPKey_ = EvpPkPtr(ephRaw, EVP_PKEY_free);

  size_t pubLen = 32;
  ephemeralPub_.resize(pubLen);
  EVP_PKEY_get_raw_public_key(ephemeralPKey_.get(), ephemeralPub_.data(),
                              &pubLen);

  return 1;
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

  return 1;
}

void CryptoHandler::set_client_ephemeral_pub(std::vector<uint8_t> epk) {
  clientEphemeralPub_ = epk;

  EVP_PKEY *clientEphRaw = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, clientEphemeralPub_.data(),
      clientEphemeralPub_.size());

  peerPkey_ = EvpPkPtr(clientEphRaw, EVP_PKEY_free);
}

int CryptoHandler::calculate_shared_key() {
  EvpCtxPtr deriveCtx = make_ctx(ephemeralPKey_.get());
  EVP_PKEY_derive_init(deriveCtx.get());

  EVP_PKEY_derive_set_peer(deriveCtx.get(), peerPkey_.get());
  size_t secretLen = 32;
  sharedKey_.resize(secretLen);

  if (EVP_PKEY_derive(deriveCtx.get(), sharedKey_.data(), &secretLen) <= 0) {
    std::cerr << "Error calculating shared secred" << std::endl;
    return -1;
  }

  return 1;
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
    get_raw_keypair(pkey_.get());

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

    return 1;
  } else {
    std::ifstream publicKeyFile(pubPath);
    std::ifstream privateKeyFile(privPath);
    std::getline(publicKeyFile, pub_key_hex_);
    std::getline(privateKeyFile, priv_key_hex_);

    priv_ = hex_to_chars(priv_key_hex_);
    pub_ = hex_to_chars(pub_key_hex_);

    EVP_PKEY *pkeyRaw = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, priv_.data(), priv_.size());

    pkey_ = EvpPkPtr(pkeyRaw, EVP_PKEY_free);

    publicKeyFile.close();
    privateKeyFile.close();
  }

  return 1;
}

int CryptoHandler::set_accessory_x(std::vector<uint8_t> a) {
  if (a.size() != 32) {
    std::cerr << "Error setting accessory" << std::endl;
    return -1;
  }
  accessoryX_ = a;

  return 1;
}

int CryptoHandler::set_signature(std::vector<uint8_t> a, std::vector<uint8_t> b,
                                 std::vector<uint8_t> c) {
  std::vector<uint8_t> messageInfo;
  messageInfo.insert(messageInfo.end(), a.begin(), a.end());
  messageInfo.insert(messageInfo.end(), b.begin(), b.end());
  messageInfo.insert(messageInfo.end(), c.begin(), c.end());

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey_.get()) != 1) {
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

std::vector<uint8_t> CryptoHandler::chacha_decrypt() {
  EVP_CIPHER_CTX *cipherCtx = EVP_CIPHER_CTX_new();
  std::vector<uint8_t> plaintext(cipherLen_);
  int outlen = 0;

  EVP_DecryptInit_ex(cipherCtx, EVP_chacha20_poly1305(), nullptr,
                     encryptKey_.data(), nonce_.data());
  EVP_DecryptUpdate(cipherCtx, plaintext.data(), &outlen, cipherText_.data(),
                    cipherLen_);
  EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_TAG, 16, authTag_.data());
  int ok = EVP_DecryptFinal_ex(cipherCtx, plaintext.data() + outlen, &outlen);

  if (ok <= 0) {
    std::cerr << "Error encrypting submessage" << std::endl;
    EVP_CIPHER_CTX_free(cipherCtx);
    return std::vector<uint8_t>();
  }

  EVP_CIPHER_CTX_free(cipherCtx);

  return plaintext;
}

std::vector<uint8_t>
CryptoHandler::chacha_encrypt(std::vector<uint8_t> payload) {
  EVP_CIPHER_CTX *cipherCtx = EVP_CIPHER_CTX_new();
  int outlen = 0;
  std::vector<uint8_t> cipherText(payload.size());

  EVP_EncryptInit_ex(cipherCtx, EVP_chacha20_poly1305(), nullptr,
                     encryptKey_.data(), nonce_.data());

  EVP_EncryptUpdate(cipherCtx, cipherText.data(), &outlen, payload.data(),
                    payload.size());
  int finalOutLen = 0;
  int ok =
      EVP_EncryptFinal_ex(cipherCtx, cipherText.data() + outlen, &finalOutLen);

  EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_GET_TAG, 16, authTag_.data());

  if (ok <= 0) {
    std::cerr << "Error encrypting submessage" << std::endl;
    EVP_CIPHER_CTX_free(cipherCtx);
    return std::vector<uint8_t>();
  }

  cipherText.insert(cipherText.end(), authTag_.begin(), authTag_.end());

  EVP_CIPHER_CTX_free(cipherCtx);

  return cipherText;
}

int CryptoHandler::hkdf_sha512(const std::string &salt,
                               const std::string &info) {
  hkdfKey_.clear();
  hkdfKey_.resize(32);

  EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);

  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA512", 0);
  params[1] = OSSL_PARAM_construct_octet_string(
      "key", (void *)sharedKey_.data(), sharedKey_.size());
  params[2] = OSSL_PARAM_construct_octet_string("salt", (void *)salt.data(),
                                                salt.size());
  params[3] = OSSL_PARAM_construct_octet_string("info", (void *)info.data(),
                                                info.size());
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kctx, hkdfKey_.data(), hkdfKey_.size(), params) <= 0) {
    std::cerr << "Error deriving KDF key" << std::endl;
    return -1;
  }

  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);

  return 1;
}

std::string CryptoHandler::get_public_hex_string() const {
  return pub_key_hex_;
}
std::vector<uint8_t> CryptoHandler::get_accessory_x() const {
  return accessoryX_;
}
std::vector<uint8_t> CryptoHandler::get_public_key() const { return pub_; }
std::vector<uint8_t> CryptoHandler::get_hkdf_key() const { return hkdfKey_; }
std::vector<uint8_t> CryptoHandler::get_shared_key() const {
  return sharedKey_;
}
std::vector<uint8_t> CryptoHandler::get_signature() const { return signature_; }
std::vector<uint8_t> CryptoHandler::get_identifier() const {
  return identifier_;
}

std::vector<uint8_t> CryptoHandler::get_ephemeral_key() const {
  return ephemeralPub_;
}

std::vector<uint8_t> CryptoHandler::get_encrypt_key() const {
  return encryptKey_;
}

std::vector<uint8_t> CryptoHandler::get_client_ephemeral_key() const {
  return clientEphemeralPub_;
}

void CryptoHandler::set_encrypt_key(std::vector<uint8_t> ek) {
  encryptKey_ = ek;
}

int CryptoHandler::set_nonce(std::string label) {
  nonce_ = {0x00, 0x00, 0x00, 0x00};
  nonce_.insert(nonce_.end(), label.begin(), label.end());

  if (nonce_.size() != 12) {
    std::cerr << "Error creating nonce, incorrect length" << std::endl;
    return -1;
  }

  return 1;
}

void CryptoHandler::set_cipher_tag(const std::vector<uint8_t> encryptedData) {
  if (encryptedData.size() >= 16) {
    cipherLen_ = encryptedData.size() - 16;

    cipherText_ = std::vector<uint8_t>(encryptedData.begin(),
                                       encryptedData.begin() + cipherLen_);
    authTag_ =
        std::vector<uint8_t>(encryptedData.end() - 16, encryptedData.end());
  }
}

void CryptoHandler::set_key(std::vector<uint8_t> ek) { hkdfKey_ = ek; }
void CryptoHandler::set_session_key(std::vector<uint8_t> ek) {
  sharedKey_ = ek;
}

int CryptoHandler::signature_verification(std::vector<uint8_t> messageInfo,
                                          std::vector<uint8_t> pubKey,
                                          std::vector<uint8_t> signature) {

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                               pubKey.data(), pubKey.size());

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);

  int result = EVP_DigestVerify(mdctx, signature.data(), signature.size(),
                                messageInfo.data(), messageInfo.size());

  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(mdctx);

  return result;
}

std::unique_ptr<CryptoHandler> create_crypto_handler() {
  return std::make_unique<CryptoHandler>();
}
