#pragma once

#include "crypto.hpp"
#include <memory>

class CipherTransporter {
public:
  CipherTransporter(u8Vec_t sk);
  ~CipherTransporter() = default;

  int set_message(char *buffer, size_t len);
  u8Vec_t cipher_length();

  int decrypt(u8Vec_t cipher, u8Vec_t aad, u8Vec_t nonce, u8Vec_t tag);

  u8Vec_t get_body() { return body_; };
  u8Vec_t get_cipher() { return u8Vec_t(body_.begin() + 2, body_.end()); };
  u8Vec_t get_decrypted() { return decrypted_; };
  u8Vec_t get_read_nonce();
  u8Vec_t get_write_nonce();
  std::string get_decoded_str();

private:
  u8Vec_t body_, decrypted_;
  size_t cipherLength_;
  u8Vec_t sharedKey_, encryptionKey_, decryptionKey_;
  size_t readCounter_, writeCounter_;
};

std::unique_ptr<CipherTransporter> create_cipher_transporter(u8Vec_t sharedKey);
