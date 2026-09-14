#pragma once

#include "crypto.hpp"
#include <memory>

struct DecryptionResult {
  u8Vec_t plaintext;
  bool success;
};

struct EncryptionResult {
  u8Vec_t ciphertext;
  u8Vec_t tag;
  bool success;
};

struct EvpCtxDeleter {
  void operator()(EVP_CIPHER_CTX *ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

class CipherTransporter {
public:
  CipherTransporter(u8Vec_t sk);
  ~CipherTransporter() = default;

  int set_message(char *buffer, size_t len);
  u8Vec_t cipher_length();
  u8Vec_t set_aad(u8Vec_t payload);

  DecryptionResult decrypt(u8Vec_t cipher, u8Vec_t aad, u8Vec_t nonce,
                           u8Vec_t tag);
  EncryptionResult encrypt(u8Vec_t payload, u8Vec_t aad, u8Vec_t nonce);

  u8Vec_t get_body() { return body_; };
  u8Vec_t get_cipher() { return u8Vec_t(body_.begin() + 2, body_.end()); };
  u8Vec_t get_read_nonce();
  u8Vec_t get_write_nonce();
  std::string get_decoded_str();

private:
  u8Vec_t body_;
  size_t cipherLength_;
  u8Vec_t sharedKey_, encryptionKey_, decryptionKey_;
  size_t readCounter_, writeCounter_;
};

std::unique_ptr<CipherTransporter> create_cipher_transporter(u8Vec_t sharedKey);
