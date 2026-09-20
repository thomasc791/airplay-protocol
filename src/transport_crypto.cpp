#include "transport_crypto.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

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

DecryptionResult CipherTransporter::decrypt_frames(char *buffer, size_t len) {
  set_message(buffer, len);

  DecryptionResult result;

  while (body_.size() >= 2) {
    u8Vec_t aad = cipher_length();
    size_t frameSize = 2 + cipherLength_ + 16;
    if (body_.size() < frameSize)
      break;

    auto [cipher, tag] = get_cipher_tag(frameSize);
    auto nonce = get_read_nonce();

    int a = decrypt(result, cipher, aad, nonce, tag);

    body_.erase(body_.begin(), body_.begin() + frameSize);
  }

  return result;
}

int CipherTransporter::decrypt(DecryptionResult &result, u8Vec_t cipher,
                               u8Vec_t aad, u8Vec_t nonce, u8Vec_t tag) {
  result.success = false;

  std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter> ctx(EVP_CIPHER_CTX_new());
  if (!ctx)
    return -1;

  int outlen = 0;
  size_t offset = result.plaintext.size();
  result.plaintext.resize(offset + cipher.size());

  int err = EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                               decryptionKey_.data(), nonce.data());
  err = EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, aad.data(), aad.size());
  err = EVP_DecryptUpdate(ctx.get(), result.plaintext.data() + offset, &outlen,
                          cipher.data(), cipher.size());
  err = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
  err =
      EVP_DecryptFinal_ex(ctx.get(), result.plaintext.data() + offset, &outlen);

  if (err <= 0) {
    std::cerr << "Error decrypting message" << std::endl;
    return err;
  }

  return err;
}

EncryptionResult CipherTransporter::encrypt(u8Vec_t payload, u8Vec_t aad,
                                            u8Vec_t nonce) {
  EncryptionResult result;
  result.success = false;

  std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter> ctx(EVP_CIPHER_CTX_new());
  if (!ctx)
    return result;

  int outlen = 0;
  result.ciphertext.resize(payload.size());
  result.tag.resize(16);

  int err = EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                               encryptionKey_.data(), nonce.data());
  err = EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, aad.data(), aad.size());
  err = EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &outlen,
                          payload.data(), payload.size());
  err = EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + outlen,
                            &outlen);

  err = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16,
                            result.tag.data());

  if (err <= 0) {
    std::cerr << "Error decrypting message" << std::endl;
    return result;
  }

  result.ciphertext.insert(result.ciphertext.begin(), aad.begin(), aad.end());
  result.ciphertext.insert(result.ciphertext.end(), result.tag.begin(),
                           result.tag.end());

  result.success = true;

  return result;
}
std::tuple<u8Vec_t, u8Vec_t>
CipherTransporter::get_cipher_tag(size_t frameSize) {

  auto cipherText = u8Vec_t(body_.begin() + 2, body_.begin() + frameSize - 16);
  auto authTag =
      u8Vec_t(body_.begin() + frameSize - 16, body_.begin() + frameSize);

  return {cipherText, authTag};
}

u8Vec_t CipherTransporter::set_aad(u8Vec_t payload) {
  uint16_t length = payload.size();
  return lil_endian(length);
}

std::unique_ptr<CipherTransporter>
create_cipher_transporter(u8Vec_t sharedKey) {
  return std::make_unique<CipherTransporter>(sharedKey);
}
