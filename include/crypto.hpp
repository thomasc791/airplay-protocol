#pragma once

#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <vector>

using u8Vec_t = std::vector<uint8_t>;

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

  int set_accessory_x(u8Vec_t a);
  int set_signature(u8Vec_t a, u8Vec_t b, u8Vec_t c);

  void set_client_ephemeral_pub(u8Vec_t epk);

  void set_encrypt_key(u8Vec_t ek);
  int generate_ephemeral_key();

  u8Vec_t chacha_decrypt(u8Vec_t cipher, u8Vec_t nonce, u8Vec_t tag);
  u8Vec_t chacha_encrypt(u8Vec_t payload);

  int set_nonce(std::string label);
  void set_session_key(u8Vec_t k);

  std::string get_public_hex_string() const;
  u8Vec_t get_accessory_x() const;
  u8Vec_t get_signature() const;
  u8Vec_t get_identifier() const;
  u8Vec_t get_public_key() const;
  u8Vec_t get_ephemeral_key() const;
  u8Vec_t get_client_ephemeral_key() const;
  u8Vec_t get_encrypt_key() const;
  u8Vec_t get_shared_key() const;
  u8Vec_t get_nonce() const { return nonce_; };

  int calculate_shared_key();

  int signature_verification(u8Vec_t identifier, u8Vec_t ltpk,
                             u8Vec_t signature);

  u8Vec_t priv_, pub_;
  u8Vec_t firstPriv_, firstPub_;

private:
  u8Vec_t identifier_, signature_, accessoryX_;
  u8Vec_t ephemeralPub_, clientEphemeralPub_;
  u8Vec_t sharedKey_, encryptKey_, nonce_, cipherText_, authTag_;

  EvpPkPtr pkey_, ephemeralPKey_, peerPkey_;
  EvpCtxPtr ctx_;
  std::string priv_key_hex_, pub_key_hex_;

  int generate_identity_keypair();
  int get_raw_keypair(EVP_PKEY *pkey);

  int store_retrieve_pkey();
  CipherCtxPtr cipherCtx_;
  size_t cipherLen_;
};

std::tuple<u8Vec_t, u8Vec_t> get_cipher_tag(const u8Vec_t encryptedData);
u8Vec_t hkdf_sha512(const std::string &salt, const std::string &info,
                    u8Vec_t key);
std::unique_ptr<CryptoHandler> create_crypto_handler();
