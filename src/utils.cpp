#include "utils.hpp"

#include <iomanip>
#include <sstream>
#include <vector>

std::vector<uint8_t> hex_to_chars(const std::string &hexStr) {
  std::vector<uint8_t> bytes;

  for (size_t i = 0; i < hexStr.length(); i += 2) {
    std::string byteString = hexStr.substr(i, 2);
    uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

std::string chars_to_hex(const std::vector<uint8_t> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (uint8_t byte : data) {
    ss << std::setw(2) << static_cast<int>(byte);
  }
  return ss.str();
}
