#include "hap_crypto.hpp"

#include <iostream>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <vector>

HAPCrypto::HAPCrypto(std::vector<uint8_t> sk)
    : sk_(sk), cipherText_({}), authTag_({}) {
  key_ = std::vector<uint8_t>(32);
}

int HAPCrypto::hkdf_sha512(const std::string &salt, const std::string &info) {
  key_.clear();
  key_.resize(32);

  std::cout << "Key length: " << key_.size() << std::endl;

  size_t outlen = key_.size();

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  EVP_PKEY_derive_init(pctx);
  EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512());
  EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const uint8_t *)salt.data(), salt.size());
  EVP_PKEY_CTX_set1_hkdf_key(pctx, sk_.data(), sk_.size());
  EVP_PKEY_CTX_add1_hkdf_info(pctx, (const uint8_t *)info.data(), info.size());
  EVP_PKEY_derive(pctx, key_.data(), &outlen);
  EVP_PKEY_CTX_free(pctx);

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

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key_.data(),
                     nonce_.data());
  EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, cipherText_.data(),
                    cipherLen_);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                      (void *)(authTag_.data()));
  int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
  EVP_CIPHER_CTX_free(ctx);

  if (ok <= 0)
    throw std::runtime_error("ChaCha20-Poly1305 tag verification failed");
  return plaintext;
}

int HAPCrypto::M5_verification(std::vector<uint8_t> identifier,
                               std::vector<uint8_t> ltpk,
                               std::vector<uint8_t> signature) {

  std::vector<uint8_t> messageInfo;
  messageInfo.reserve(
      key_.size() + identifier.size() +
      ltpk.size()); // Optioneel, voorkomt extra geheugenallocaties

  messageInfo.insert(messageInfo.end(), key_.begin(), key_.end());
  messageInfo.insert(messageInfo.end(), identifier.begin(), identifier.end());
  messageInfo.insert(messageInfo.end(), ltpk.begin(), ltpk.end());

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                               ltpk.data(), ltpk.size());

  // 2. Maak een verificatie-context aan
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  // 3. Initialiseer en verifieer in één keer (Ed25519 ondersteunt geen
  // streaming update)
  EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);

  // messageInfo is de samengevoegde buffer uit stap 2
  // signature is de 64-byte vector uit TLV 0x0A
  int result = EVP_DigestVerify(mdctx, signature.data(), signature.size(),
                                messageInfo.data(), messageInfo.size());

  return result;
}

std::unique_ptr<HAPCrypto> create_hap_handler(std::vector<uint8_t> sk) {
  return std::make_unique<HAPCrypto>(sk);
}
