#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> hex_to_chars(const std::string &hexStr);
std::string chars_to_hex(const std::vector<uint8_t> &data);

template <typename T> std::vector<uint8_t> lil_endian(T num);

std::string remove_colon(std::string str);
