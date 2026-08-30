#pragma once

#include <cstdint>
#include <vector>

class HAPCrypto {
public:
  HAPCrypto(std::vector<uint8_t>);
  ~HAPCrypto();

  std::vector<uint8_t> sharedKey;

private:
};
