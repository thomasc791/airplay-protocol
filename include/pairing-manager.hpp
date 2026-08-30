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
      std::pair<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>> entry);

private:
  std::map<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>> pairingMap_;
  std::string fName = "paired.info";
  std::filesystem::path filePath_;

  std::pair<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>>
  read_pair(std::stringstream &pair);
};

std::unique_ptr<PairingManager> create_pairing_manager();
std::string to_hex(const std::vector<uint8_t> &data);
std::vector<uint8_t> from_hex(const std::string &hexStr);
