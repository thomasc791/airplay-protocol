#pragma once

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

std::vector<uint8_t> hex_to_chars(const std::string &hexStr);

template <class T> std::string chars_to_hex(const std::vector<T> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (T byte : data) {
    ss << std::setw(2) << static_cast<int>(byte);
  }
  return ss.str();
}

std::string chars_to_hex_c(const uint8_t *data, size_t len);

template <typename T> std::vector<uint8_t> lil_endian(T num) {
  size_t numBytes = sizeof(T) / sizeof(uint8_t);
  std::vector<uint8_t> lilEndianVec(numBytes);

  for (size_t i = 0; i < numBytes; i++)
    lilEndianVec[i] = num >> (i * 8);

  return lilEndianVec;
}

std::string remove_colon(std::string str);
