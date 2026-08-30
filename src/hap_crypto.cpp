#include "hap_crypto.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <vector>

HAPCrypto::HAPCrypto(std::vector<uint8_t> sk) : sharedKey(sk) {}
