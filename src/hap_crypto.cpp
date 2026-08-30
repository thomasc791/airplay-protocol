#include "hap_crypto.hpp"

#include <iostream>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <vector>

HAPCrypto::HAPCrypto(std::vector<uint8_t> sk) : sk_(sk) {
  key_ = std::vector<uint8_t>(32);
}
HAPCrypto::~HAPCrypto() {}

int HAPCrypto::hkdf_sha512(const std::string &salt, const std::string &info) {
  key_.clear();

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

std::vector<uint8_t>
HAPCrypto::chacha_decrypt(const std::vector<uint8_t> &ciphertextWithTag) {
  size_t ctLen =
      ciphertextWithTag.size() - 16; // last 16 bytes are the Poly1305 tag
  std::vector<uint8_t> plaintext(ctLen);
  int outlen = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key_.data(),
                     nonce_.data());
  EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertextWithTag.data(),
                    ctLen);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                      (void *)(ciphertextWithTag.data() + ctLen));
  int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
  EVP_CIPHER_CTX_free(ctx);

  if (ok <= 0)
    throw std::runtime_error("ChaCha20-Poly1305 tag verification failed");
  return plaintext;
}

std::unique_ptr<HAPCrypto> create_hap_handler(std::vector<uint8_t> sk) {
  return std::make_unique<HAPCrypto>(sk);
}
