#include "pairing-manager.hpp"
#include "utils.hpp"

#include <cstdio>
#include <fstream>
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
  } else {
    fs::path filePath = keyDir / "identity";

    fs::path pubPath = filePath;
    fs::path privPath = filePath;
    pubPath += ".pub";
    privPath += ".priv";

    if (!fs::exists(keyDir)) {
      if (!fs::create_directory(keyDir)) {
        std::cerr << "Failed to create directory at " << keyDir << std::endl;
        return;
      }
    }

    std::string pubKeyHex, privKeyHex;

    std::ifstream publicKeyFile(pubPath);
    std::ifstream privateKeyFile(privPath);
    std::getline(publicKeyFile, pubKeyHex);
    std::getline(privateKeyFile, privKeyHex);

    pub_ = hex_to_chars(pubKeyHex);
    priv_ = hex_to_chars(privKeyHex);

    publicKeyFile.close();
    privateKeyFile.close();
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
      fout << chars_to_hex(k);
      fout << "," << chars_to_hex(v);
      fout << std::endl;
    }

    fout.close();
  }
  std::cout << "Set Public Keys" << std::endl;
}

void PairingManager::add_paired_device(
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> entry) {
  pairingMap_[entry.first] = entry.second;
}

std::tuple<bool, std::vector<uint8_t>>
PairingManager::get_device_key(std::vector<uint8_t> identifier) {

  for (auto [k, v] : pairingMap_) {
    std::cout << chars_to_hex(k) << std::endl;
  }

  if (pairingMap_.count(identifier))
    return {true, pairingMap_[identifier]};

  return {false, std::vector<uint8_t>()};
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
PairingManager::read_pair(std::stringstream &pair) {
  std::string identifier;
  std::string publicKey;
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
    }
    i++;
  }

  std::vector<uint8_t> identifierVec = hex_to_chars(identifier);
  std::vector<uint8_t> pkVec = hex_to_chars(publicKey);

  return {identifierVec, pkVec};
}

std::vector<uint8_t> PairingManager::get_public_key() { return pub_; }

std::shared_ptr<PairingManager> create_pairing_manager() {
  return std::make_shared<PairingManager>();
}
