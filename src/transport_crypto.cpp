#include "transport_crypto.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <iostream>

CipherTransporter::CipherTransporter(u8Vec_t sk)
    : sharedKey_(sk), readCounter_(0), writeCounter_(0) {
  decryptionKey_ =
      hkdf_sha512("Control-Salt", "Control-Write-Encryption-Key", sharedKey_);
  encryptionKey_ =
      hkdf_sha512("Control-Salt", "Control-Read-Encryption-Key", sharedKey_);
}

int CipherTransporter::set_message(char *buffer, size_t len) {
  body_ = u8Vec_t(reinterpret_cast<const uint8_t *>(buffer),
                  reinterpret_cast<const uint8_t *>(buffer) + len);

  return 1;
}

u8Vec_t CipherTransporter::get_read_nonce() {
  u8Vec_t nonce(12);

  for (size_t i = 0; i < 4; i++)
    nonce[4 + i] = readCounter_ >> (i * 8);

  readCounter_++;
  return nonce;
}

u8Vec_t CipherTransporter::get_write_nonce() {
  u8Vec_t nonce(12);

  for (size_t i = 0; i < 4; i++)
    nonce[4 + i] = writeCounter_ >> (i * 8);

  writeCounter_++;
  return nonce;
}

u8Vec_t CipherTransporter::cipher_length() {
  cipherLength_ = body_[1] << 8;
  cipherLength_ |= body_[0];

  return u8Vec_t(body_.begin(), body_.begin() + 2);
}

int CipherTransporter::decrypt(u8Vec_t cipher, u8Vec_t aad, u8Vec_t nonce,
                               u8Vec_t tag) {
  int err = 1;
  EVP_CIPHER_CTX *cipherCtx = EVP_CIPHER_CTX_new();
  u8Vec_t plaintext(cipherLength_);
  int outlen = 0;

  err = EVP_DecryptInit_ex(cipherCtx, EVP_chacha20_poly1305(), nullptr,
                           decryptionKey_.data(), nonce.data());
  err = EVP_DecryptUpdate(cipherCtx, nullptr, &outlen, aad.data(), aad.size());
  err = EVP_DecryptUpdate(cipherCtx, plaintext.data(), &outlen, cipher.data(),
                          cipher.size());
  err = EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
  err = EVP_DecryptFinal_ex(cipherCtx, plaintext.data() + outlen, &outlen);

  if (err <= 0) {
    std::cerr << "Error decrypting message" << std::endl;
    EVP_CIPHER_CTX_free(cipherCtx);
    return err;
  }

  EVP_CIPHER_CTX_free(cipherCtx);
  decrypted_ = plaintext;

  return 1;
}

std::unique_ptr<CipherTransporter>
create_cipher_transporter(u8Vec_t sharedKey) {
  return std::make_unique<CipherTransporter>(sharedKey);
}
