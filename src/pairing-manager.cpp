#include "pairing-manager.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

PairingManager::PairingManager() : pairingMap_({}) {
  std::string pairStr;

  const char *xdg_data = std::getenv("XDG_DATA_HOME");
  fs::path baseDir =
      xdg_data ? fs::path(xdg_data) : fs::path(std::getenv("HOME"));
  fs::path keyDir = baseDir / "airplay-protocol";
  filePath_ = keyDir / fName;

  if (!fs::exists(keyDir)) {
    if (!fs::create_directory(keyDir)) {
      std::cerr << "Failed to create directory at " << keyDir << std::endl;

      return;
    }
  }

  std::ifstream fin(filePath_);
  if (!fs::exists(filePath_)) {
  } else {
    if (fin.is_open()) {
      while (std::getline(fin, pairStr)) {
        std::stringstream pairss;
        pairss << pairStr;
        auto pair = read_pair(pairss);
        pairingMap_.emplace(pair);
      }
    }
  }
  fin.close();
}

PairingManager::~PairingManager() {
  std::ofstream fout(filePath_);
  std::string pairStr;

  if (fout.is_open()) {
    for (auto [k, v] : pairingMap_) {
      if (k.size() <= 0)
        break;
      fout << to_hex(k);
      for (auto vv : v)
        fout << "," << to_hex(vv);
      fout << std::endl;
    }

    fout.close();
  }
  std::cout << "Set Public Keys" << std::endl;
}

void PairingManager::add_paired_device(
    std::pair<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>> entry) {
  pairingMap_[entry.first] = entry.second;
}

std::pair<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>>
PairingManager::read_pair(std::stringstream &pair) {
  std::string identifier;
  std::string publicKey;
  std::string signature;
  std::string kv;
  size_t i = 0;
  while (std::getline(pair, kv, ',')) {
    switch (i) {
    case 0:
      identifier = kv;
      break;
    case 1:
      publicKey = kv;
      break;
    case 2:
      signature = kv;
      break;
    }
    i++;
  }

  std::vector<uint8_t> identifierVec = from_hex(identifier);
  std::vector<uint8_t> pkVec = from_hex(publicKey);
  std::vector<uint8_t> signatureVec = from_hex(signature);

  return {identifierVec, {pkVec, signatureVec}};
}

std::unique_ptr<PairingManager> create_pairing_manager() {
  return std::make_unique<PairingManager>();
}

std::string to_hex(const std::vector<uint8_t> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (uint8_t byte : data) {
    ss << std::setw(2) << static_cast<int>(byte);
  }
  return ss.str();
}

std::vector<uint8_t> from_hex(const std::string &hexStr) {
  std::vector<uint8_t> bytes;

  for (size_t i = 0; i < hexStr.length(); i += 2) {
    std::string byteString = hexStr.substr(i, 2);
    uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}
