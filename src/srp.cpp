#include "srp.hpp"
#include <cstdio>
#include <iostream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

constexpr int SALT_BITS = 128;
constexpr int RAND_BITS = 512;

SRPHandler::SRPHandler()
    : ctx_(nullptr, BN_CTX_free), N_(nullptr, BN_free), g_(nullptr, BN_free),
      x_(nullptr, BN_free), k_(nullptr, BN_free), s_(nullptr, BN_free),
      v_(nullptr, BN_free), b_(nullptr, BN_free), B_(nullptr, BN_free),
      a_(nullptr, BN_free), A_(nullptr, BN_free), u_(nullptr, BN_free),
      S_(nullptr, BN_free), K_(nullptr, BN_free), M1_(nullptr, BN_free),
      M1Expected_(nullptr, BN_free), M2_(nullptr, BN_free) {

  ctx_ = CtxPtr(BN_CTX_new(), BN_CTX_free);

  BIGNUM *rawN = nullptr;
  BN_hex2bn(&rawN, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
  N_ = BnPtr(rawN, BN_free);

  padLen = BN_num_bytes(N_.get());

  BIGNUM *rawg = nullptr;
  BN_dec2bn(&rawg, "5");
  g_ = BnPtr(rawg, BN_free);

  k_ = H({N_.get(), g_.get()}, true);

  s_ = make_bn();
  v_ = make_bn();

  BnPtr interAB = make_bn();
  BnPtr interBB = make_bn();
  BnPtr interCB = make_bn();

  b_ = make_bn();
  B_ = make_bn();
  a_ = make_bn();
  S_ = make_bn();

  BN_rand(s_.get(), SALT_BITS, -1, 0);

  std::vector<uint8_t> innerDigest =
      H_bytes(username_ + std::string(":") + "3939");
  std::vector<uint8_t> saltBytes =
      get_salt(); // the padded 16-byte value, same as sent on wire
  std::vector<uint8_t> xDigest = H_bytes({saltBytes, innerDigest});
  x_ = BnPtr(BN_bin2bn(xDigest.data(), xDigest.size(), nullptr), BN_free);

  BN_mod_exp(v_.get(), g_.get(), x_.get(), N_.get(), ctx_.get());

  BN_rand(b_.get(), RAND_BITS, -1, 0);

  BN_mul(interAB.get(), k_.get(), v_.get(), ctx_.get());
  BN_mod_exp(interBB.get(), g_.get(), b_.get(), N_.get(), ctx_.get());
  BN_add(interCB.get(), interAB.get(), interBB.get());

  BN_mod(B_.get(), interCB.get(), N_.get(), ctx_.get());
}

SRPHandler::~SRPHandler() {}

std::vector<uint8_t> SRPHandler::get_salt() {
  return pad_to(bn_to_bytes(s_.get()), 16);
}

std::vector<uint8_t> SRPHandler::get_public_key() {
  return bn_to_bytes(B_.get());
}

std::vector<uint8_t> SRPHandler::sha512(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> digest(EVP_MD_size(EVP_sha512()));
  unsigned int len = 0;

  EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha512(),
             nullptr);
  return digest;
}

BnPtr SRPHandler::H(const std::vector<BIGNUM *> &args, bool pad) {
  std::vector<uint8_t> digest = H_bytes(args, pad);
  return BnPtr(BN_bin2bn(digest.data(), digest.size(), nullptr), BN_free);
}

BnPtr SRPHandler::H(const std::string &a, const std::string &b,
                    const std::string &sep) {

  std::vector<uint8_t> byteArgs = {};

  byteArgs.insert(byteArgs.end(), a.begin(), a.end());
  byteArgs.insert(byteArgs.end(), sep.begin(), sep.end());
  byteArgs.insert(byteArgs.end(), b.begin(), b.end());

  std::vector<uint8_t> digest = sha512(byteArgs);
  return BnPtr(BN_bin2bn(digest.data(), digest.size(), nullptr), BN_free);
}

std::vector<uint8_t> SRPHandler::H_bytes(const std::vector<BIGNUM *> &args,
                                         bool pad) {
  std::vector<uint8_t> byteArgs;
  for (auto arg : args) {
    std::vector<uint8_t> chunk = bn_to_bytes(arg);
    if (pad)
      chunk = pad_to(chunk, padLen);

    byteArgs.insert(byteArgs.end(), chunk.begin(), chunk.end());
  }
  return sha512(byteArgs);
}

std::vector<uint8_t>
SRPHandler::H_bytes(const std::vector<std::vector<uint8_t>> &parts) {
  std::vector<uint8_t> byteArgs;
  for (auto &p : parts)
    byteArgs.insert(byteArgs.end(), p.begin(), p.end());
  return sha512(byteArgs);
}

std::vector<uint8_t> SRPHandler::H_bytes(const std::string &s) {
  return sha512(std::vector<uint8_t>(s.begin(), s.end()));
}

std::vector<uint8_t> SRPHandler::bn_to_bytes(BIGNUM *bn) {
  std::vector<uint8_t> buf(BN_num_bytes(bn));
  BN_bn2bin(bn, buf.data());
  return buf;
}

std::vector<uint8_t> SRPHandler::pad_to(std::vector<uint8_t> b, size_t width) {
  if (b.size() < width) {
    b.insert(b.begin(), width - b.size(), 0x00);
  }

  return b;
}

int SRPHandler::set_A(std::vector<uint8_t> A) {
  BIGNUM *raw = BN_bin2bn(A.data(), A.size(), nullptr);
  if (!raw)
    return -1;

  A_ = BnPtr(raw, BN_free);

  rawA_ = A;
  return 0;
}

int SRPHandler::set_M1(std::vector<uint8_t> M1) {
  BIGNUM *raw = BN_bin2bn(M1.data(), M1.size(), nullptr);
  if (!raw)
    return -1;

  M1_ = BnPtr(raw, BN_free);
  rawM1_ = M1;
  return 0;
}

int SRPHandler::client_proof() {
  BnPtr interAS = make_bn();
  BnPtr interBS = make_bn();
  BnPtr interCS = make_bn();

  u_ = H({A_.get(), B_.get()}, true);

  BN_mod_exp(interAS.get(), v_.get(), u_.get(), N_.get(), ctx_.get());
  BN_mul(interBS.get(), A_.get(), interAS.get(), ctx_.get());
  BN_mod_exp(interCS.get(), interBS.get(), b_.get(), N_.get(), ctx_.get());
  int err = BN_mod(S_.get(), interCS.get(), N_.get(), ctx_.get());

  if (err < 0)
    throw std::runtime_error("Error creating S");

  rawK_ = H_bytes({S_.get()});
  BIGNUM *Kraw = BN_bin2bn(rawK_.data(), rawK_.size(), nullptr);
  if (!Kraw) {
    std::cerr << "Could not create K" << std::endl;
    return -1;
  }
  K_ = BnPtr(Kraw, BN_free);

  std::vector<uint8_t> hN = H_bytes({N_.get()});
  std::vector<uint8_t> hg = H_bytes({g_.get()});
  std::vector<uint8_t> hNxorHg(hN.size());
  for (size_t i = 0; i < hN.size(); i++)
    hNxorHg[i] = hN[i] ^ hg[i];

  std::vector<uint8_t> sBytes = get_salt();
  std::vector<uint8_t> ABytes = bn_to_bytes(A_.get());
  std::vector<uint8_t> BBytes = get_public_key();

  std::vector<uint8_t> M1ExpectedBytes =
      H_bytes({hNxorHg, H_bytes(username_), sBytes, ABytes, BBytes, rawK_});

  BIGNUM *rawM1Expected =
      BN_bin2bn(M1ExpectedBytes.data(), M1ExpectedBytes.size(), nullptr);
  if (!rawM1Expected)
    return -1;

  M1Expected_ = BnPtr(rawM1Expected, BN_free);

  return 0;
}

bool SRPHandler::validate_M1() {
  std::vector<uint8_t> M1ExpectedBytes(BN_num_bytes(M1Expected_.get()));
  std::vector<uint8_t> M1Bytes(BN_num_bytes(M1_.get()));

  BN_bn2bin(M1Expected_.get(), M1ExpectedBytes.data());

  BN_bn2bin(M1_.get(), M1Bytes.data());

  for (auto b : M1ExpectedBytes)
    printf("%02x ", b);
  std::cout << std::endl;
  for (auto b : M1Bytes)
    printf("%02x ", b);
  std::cout << std::endl;

  return (M1ExpectedBytes == M1Bytes);
}

int SRPHandler::create_M2() {
  std::vector<uint8_t> M2Bytes = H_bytes({rawA_, rawM1_, rawK_});
  // M2_ = H({A_.get(), M1_.get(), K_.get()});
  BIGNUM *M2raw = BN_bin2bn(M2Bytes.data(), M2Bytes.size(), nullptr);

  if (!M2raw) {
    std::cerr << "Could not create M2" << std::endl;
    return -1;
  }
  M2_ = BnPtr(M2raw, BN_free);

  return 0;
}

std::vector<uint8_t> SRPHandler::get_proof() { return bn_to_bytes(M2_.get()); }

std::unique_ptr<SRPHandler> create_srp_handler() {
  return std::make_unique<SRPHandler>();
}
