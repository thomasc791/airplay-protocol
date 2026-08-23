#include "srp.hpp"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <vector>

constexpr int SALT_BITS = 128;
constexpr int RAND_BITS = 512;

SRPHandler::SRPHandler()
    : N_(nullptr, BN_free), g_(nullptr, BN_free), x_(nullptr, BN_free),
      k_(nullptr, BN_free), s_(nullptr, BN_free), v_(nullptr, BN_free),
      b_(nullptr, BN_free), B_(nullptr, BN_free), a_(nullptr, BN_free),
      A_(nullptr, BN_free) {

  CtxPtr ctx(BN_CTX_new(), BN_CTX_free);

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
  BN_rand(s_.get(), SALT_BITS, -1, 0);

  x_ = H({s_.get(), H("Pair-Setup", "3939", ":").get()});

  v_ = make_bn();
  BN_mod_exp(v_.get(), g_.get(), x_.get(), N_.get(), ctx.get());

  b_ = make_bn();
  BN_rand(b_.get(), RAND_BITS, -1, 0);

  BnPtr interAB = make_bn();
  BnPtr interBB = make_bn();
  BnPtr interCB = make_bn();

  BN_mul(interAB.get(), k_.get(), v_.get(), ctx.get());
  BN_mod_exp(interBB.get(), g_.get(), b_.get(), N_.get(), ctx.get());
  BN_add(interCB.get(), interAB.get(), interBB.get());

  B_ = make_bn();
  BN_mod(B_.get(), interCB.get(), N_.get(), ctx.get());
}

SRPHandler::~SRPHandler() {}

std::vector<uint8_t> SRPHandler::get_salt() {
  std::vector<uint8_t> salt;
  BN_bn2bin(s_.get(), salt.data());

  return salt;
}

std::vector<uint8_t> SRPHandler::get_public_key() {
  std::vector<uint8_t> pk;
  BN_bn2bin(B_.get(), pk.data());

  return pk;
}

std::vector<uint8_t> SRPHandler::sha512(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> digest(EVP_MD_size(EVP_sha512()));
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha512(),
             nullptr);
  return digest;
}

BnPtr SRPHandler::H(const std::vector<BIGNUM *> &args, bool pad) {
  std::vector<uint8_t> byteArgs = {};
  for (auto arg : args) {
    std::vector<uint8_t> currentByteArg = bn_to_bytes(arg);

    if (pad) {
      currentByteArg = pad_to(currentByteArg, padLen);
    }

    byteArgs.insert(byteArgs.end(), currentByteArg.begin(),
                    currentByteArg.end());
  }

  std::vector<uint8_t> digest = sha512(byteArgs);
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
