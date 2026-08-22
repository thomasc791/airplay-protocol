#include "utils.hpp"

#include <iomanip>
#include <sstream>

std::string chars_to_string(const uint8_t *c, size_t len) {
  std::ostringstream oss;
  for (size_t i = 0; i < len; ++i) {
    // Convert each byte to a 2-character hex format
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(c[i]);
  }
  return oss.str();
}
