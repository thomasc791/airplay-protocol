#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <utility>
#include <vector>
class PairingManager {
public:
  PairingManager();
  ~PairingManager();

  void add_paired_device(
      std::pair<std::vector<uint8_t>, std::vector<uint8_t>> entry);

  std::tuple<bool, std::vector<uint8_t>>
  get_device_key(std::vector<uint8_t> identifier);
  std::vector<uint8_t> get_public_key();

private:
  std::map<std::vector<uint8_t>, std::vector<uint8_t>> pairingMap_;
  std::vector<uint8_t> pub_, priv_;
  std::string fName = "paired.info";
  std::filesystem::path filePath_;

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  read_pair(std::stringstream &pair);
};

std::shared_ptr<PairingManager> create_pairing_manager();
std::string to_hex(const std::vector<uint8_t> &data);
std::vector<uint8_t> hex_to_chars(const std::string &hexStr);
