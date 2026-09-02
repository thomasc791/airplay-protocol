#include "hap_crypto.hpp"

#include <iostream>
#include <openssl/kdf.h>
#include <stdexcept>
#include <vector>

HAPCrypto::HAPCrypto(std::vector<uint8_t> sk)
    : sk_(sk), cipherText_({}), authTag_({}) {
  key_ = std::vector<uint8_t>(32);

  cipherCtx_ = EVP_CIPHER_CTX_new();
}

HAPCrypto::~HAPCrypto() { EVP_CIPHER_CTX_free(cipherCtx_); }

int HAPCrypto::hkdf_sha512(const std::string &salt, const std::string &info) {
  key_.clear();
  key_.resize(32);

  EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);

  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA512", 0);
  params[1] =
      OSSL_PARAM_construct_octet_string("key", (void *)sk_.data(), sk_.size());
  params[2] = OSSL_PARAM_construct_octet_string("salt", (void *)salt.data(),
                                                salt.size());
  params[3] = OSSL_PARAM_construct_octet_string("info", (void *)info.data(),
                                                info.size());
  params[4] = OSSL_PARAM_construct_end();

  EVP_KDF_derive(kctx, key_.data(), key_.size(), params);

  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);

  return 0;
}

int HAPCrypto::set_nonce(std::string label) {
  nonce_ = {0x00, 0x00, 0x00, 0x00};
  nonce_.insert(nonce_.end(), label.begin(), label.end());

  if (nonce_.size() != 12) {
    std::cerr << "Error creating nonce, incorrect length" << std::endl;
    return -1;
  }

  return 0;
}

void HAPCrypto::set_cipher_tag(const std::vector<uint8_t> encryptedData) {
  if (encryptedData.size() >= 16) {
    cipherLen_ = encryptedData.size() - 16;

    cipherText_ = std::vector<uint8_t>(encryptedData.begin(),
                                       encryptedData.begin() + cipherLen_);
    authTag_ =
        std::vector<uint8_t>(encryptedData.end() - 16, encryptedData.end());
  }
}

std::vector<uint8_t> HAPCrypto::chacha_decrypt() {
  std::vector<uint8_t> plaintext(cipherLen_);
  int outlen = 0;

  EVP_DecryptInit_ex(cipherCtx_, EVP_chacha20_poly1305(), nullptr, key_.data(),
                     nonce_.data());
  EVP_DecryptUpdate(cipherCtx_, plaintext.data(), &outlen, cipherText_.data(),
                    cipherLen_);
  EVP_CIPHER_CTX_ctrl(cipherCtx_, EVP_CTRL_AEAD_SET_TAG, 16,
                      (void *)(authTag_.data()));
  int ok = EVP_DecryptFinal_ex(cipherCtx_, plaintext.data() + outlen, &outlen);

  if (ok <= 0)
    throw std::runtime_error("ChaCha20-Poly1305 tag verification failed");
  return plaintext;
}

std::vector<uint8_t> HAPCrypto::chacha_encrypt(std::vector<uint8_t> payload) {
  int outlen = 0;
  std::vector<uint8_t> cipherText(payload.size());
  EVP_EncryptInit_ex(cipherCtx_, EVP_chacha20_poly1305(), nullptr, key_.data(),
                     nonce_.data());
  EVP_EncryptUpdate(cipherCtx_, cipherText.data(), &outlen, payload.data(),
                    payload.size());
  int finalOutLen = 0;
  int ok =
      EVP_EncryptFinal_ex(cipherCtx_, cipherText.data() + outlen, &finalOutLen);

  EVP_CIPHER_CTX_ctrl(cipherCtx_, EVP_CTRL_AEAD_GET_TAG, 16, authTag_.data());

  if (ok <= 0) {
    std::cerr << "Error encrypting submessage" << std::endl;
    return std::vector<uint8_t>();
  }

  cipherText.insert(cipherText.end(), authTag_.begin(), authTag_.end());

  return cipherText;
}

int HAPCrypto::M5_verification(std::vector<uint8_t> identifier,
                               std::vector<uint8_t> ltpk,
                               std::vector<uint8_t> signature) {

  std::vector<uint8_t> messageInfo;
  messageInfo.reserve(key_.size() + identifier.size() + ltpk.size());

  messageInfo.insert(messageInfo.end(), key_.begin(), key_.end());
  messageInfo.insert(messageInfo.end(), identifier.begin(), identifier.end());
  messageInfo.insert(messageInfo.end(), ltpk.begin(), ltpk.end());

  if (ltpk.size() != 32)
    throw std::runtime_error(
        "Long Term Public Key is not 32 bytes long. Quitting");

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                               ltpk.data(), ltpk.size());

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);

  int result = EVP_DigestVerify(mdctx, signature.data(), signature.size(),
                                messageInfo.data(), messageInfo.size());

  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(mdctx);

  return result;
}

void HAPCrypto::set_key(std::vector<uint8_t> ek) { key_ = ek; }
void HAPCrypto::set_encrypt_key(std::vector<uint8_t> ek) { encryptKey_ = ek; }

std::vector<uint8_t> HAPCrypto::get_key() const { return key_; };
std::vector<uint8_t> HAPCrypto::get_encrypt_key() const { return encryptKey_; }

std::unique_ptr<HAPCrypto> create_hap_handler(std::vector<uint8_t> sk) {
  return std::make_unique<HAPCrypto>(sk);
}
