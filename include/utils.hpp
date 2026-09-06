#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> hex_to_chars(const std::string &hexStr);
std::string chars_to_hex(const std::vector<uint8_t> &data);

template <typename T> std::vector<uint8_t> lil_endian(T num) {
  size_t numBytes = sizeof(T) / sizeof(uint8_t);
  std::vector<uint8_t> lilEndianVec(numBytes);

  for (size_t i = 1; i <= numBytes; i++)
    lilEndianVec[numBytes - i] = num >> ((i - 1) * 8);

  return lilEndianVec;
}

std::string remove_colon(std::string str);
