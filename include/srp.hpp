#pragma once

#include <cstdint>
#include <string>

class SRPHandler {
public:
  SRPHandler();
  ~SRPHandler();

private:
  std::string N;
  int64_t g;
  int64_t x;
  int64_t v;
  uint8_t pub[32], priv[32];
};
