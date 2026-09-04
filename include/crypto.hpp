#pragma once

#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <vector>

using EvpCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using CipherCtxPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

inline EvpCtxPtr make_ctx(int e) {
  return EvpCtxPtr(EVP_PKEY_CTX_new_id(e, nullptr), EVP_PKEY_CTX_free);
}
inline EvpCtxPtr make_ctx(EVP_PKEY *pkey) {
  return EvpCtxPtr(EVP_PKEY_CTX_new(pkey, nullptr), EVP_PKEY_CTX_free);
}
inline CipherCtxPtr make_cipher_ctx() {
  return CipherCtxPtr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
}

using EvpPkPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

class CryptoHandler {
public:
  CryptoHandler();
  ~CryptoHandler();

  int set_accessory_x(std::vector<uint8_t> a);
  int set_signature(std::vector<uint8_t> a, std::vector<uint8_t> b,
                    std::vector<uint8_t> c);

  void set_client_ephemeral_pub(std::vector<uint8_t> epk);

  void set_cipher_tag(const std::vector<uint8_t> encryptedData);
  void set_encrypt_key(std::vector<uint8_t> ek);

  std::vector<uint8_t> chacha_decrypt();
  std::vector<uint8_t> chacha_encrypt(std::vector<uint8_t> payload);

  int set_nonce(std::string label);
  void set_key(std::vector<uint8_t> ek);
  void set_session_key(std::vector<uint8_t> k);

  std::string get_public_hex_string() const;
  std::vector<uint8_t> get_accessory_x() const;
  std::vector<uint8_t> get_signature() const;
  std::vector<uint8_t> get_identifier() const;
  std::vector<uint8_t> get_public_key() const;
  std::vector<uint8_t> get_ephemeral_key() const;
  std::vector<uint8_t> get_client_ephemeral_key() const;
  std::vector<uint8_t> get_encrypt_key() const;
  std::vector<uint8_t> get_hkdf_key() const;
  std::vector<uint8_t> get_shared_key() const;

  int calculate_shared_key();
  int hkdf_sha512(const std::string &salt, const std::string &info);

  int signature_verification(std::vector<uint8_t> identifier,
                             std::vector<uint8_t> ltpk,
                             std::vector<uint8_t> signature);

private:
  std::vector<uint8_t> identifier_, signature_, accessoryX_;
  std::vector<uint8_t> priv_, pub_;
  std::vector<uint8_t> ephemeralPub_, clientEphemeralPub_;
  std::vector<uint8_t> sharedKey_, encryptKey_, hkdfKey_, nonce_, cipherText_,
      authTag_;

  EvpPkPtr pkey_, ephemeralPKey_, peerPkey_;
  EvpCtxPtr ctx_;
  std::string priv_key_hex_, pub_key_hex_;

  int generate_identity_keypair();
  int generate_ephemeral_key();
  int get_raw_keypair(EVP_PKEY *pkey);

  int store_retrieve_pkey();
  CipherCtxPtr cipherCtx_;
  size_t cipherLen_;
};

std::shared_ptr<CryptoHandler> create_crypto_handler();
