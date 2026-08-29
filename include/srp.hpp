#pragma once

#include <cstdint>
#include <memory>
#include <openssl/bn.h>
#include <string>
#include <vector>

using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
inline BnPtr make_bn() { return BnPtr(BN_new(), BN_free); }

using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

class SRPHandler {
public:
  SRPHandler();
  ~SRPHandler();

  BnPtr H(const std::vector<BIGNUM *> &args, bool pad = false);
  BnPtr H(const std::string &a, const std::string &b,
          const std::string &sep = "");

  std::vector<uint8_t> H_bytes(const std::vector<BIGNUM *> &args,
                               bool pad = false);
  std::vector<uint8_t> H_bytes(const std::vector<std::vector<uint8_t>> &parts);
  std::vector<uint8_t> H_bytes(const std::string &s);

  std::vector<uint8_t> get_salt();
  std::vector<uint8_t> get_public_key();
  std::vector<uint8_t> get_proof();

  int set_A(std::vector<uint8_t> A);
  int set_M1(std::vector<uint8_t> M1);
  int client_proof();
  bool validate_M1();
  int create_M2();

private:
  CtxPtr ctx_;
  BnPtr N_;
  BnPtr g_;
  BnPtr x_;
  BnPtr k_;
  BnPtr s_;
  BnPtr v_;
  BnPtr b_;
  BnPtr B_;
  BnPtr a_;
  BnPtr A_;
  BnPtr u_;
  BnPtr S_;
  BnPtr K_;
  BnPtr M1_;
  BnPtr M1Expected_;
  BnPtr M2_;

  std::vector<uint8_t> rawA_, rawM1_, rawK_;
  std::string username_ = "Pair-Setup";

  size_t padLen;

  std::vector<uint8_t> bn_to_bytes(BIGNUM *bn);
  std::vector<uint8_t> pad_to(std::vector<uint8_t> b, size_t width);

  std::vector<uint8_t> sha512(const std::vector<uint8_t> &data);
};

std::unique_ptr<SRPHandler> create_srp_handler();
