#include "airplay_server.hpp"
#include "crypto.hpp"
#include "flags.hpp"
#include "pairing_manager.hpp"
#include "rtsp.hpp"
#include "socket.hpp"
#include "transport_crypto.hpp"
#include "utils.hpp"

#include <avahi-client/client.h>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <unistd.h>

AirPlayServer::AirPlayServer(const std::string &device_name, uint16_t port)
    : port_(port), deviceName_(device_name) {

  deviceID_ = get_system_mac_address();
  pairingManager_ = create_pairing_manager();

  pi_ = "202e8e4d-fd93-45da-af09-26850b417ad6";
}

AirPlayServer::~AirPlayServer() { stop(); }

bool AirPlayServer::start() {
  mdns_ = create_mdns_service();
  featureFlags_ = create_feature_flags();
  statusFlags_ = create_status_flags();

  if (mdns_->start()) {
    if (publish_airplay_service() < 0)
      std::cerr << "Failed to publish airplay service." << std::endl;
    std::cout << "[AirPlayServer] Published AirPlay mDNS service: "
              << deviceName_ << " on port " << 7000 << std::endl;

    if (publish_raop_service() < 0)
      std::cerr << "Failed to publish raop service." << std::endl;
    std::cout << "[AirPlayServer] Published RAOP mDNS service: " << deviceName_
              << " on port " << 5000 << std::endl;
  }

  auto callback = [this](int id) { this->handle_client(id); };

  running_ = true;

  airplayServer_ = std::make_unique<TCPServer>(callback, "AirPlayServer", 7000);
  std::thread([this]() { airplayServer_->start(); }).detach();

  return true;
}

int AirPlayServer::publish_airplay_service() {
  std::map<std::string, std::string> txt = {
      {"acl", "0"},
      {"deviceid", deviceID_},
      {"features", featureFlags_->get_hex()},
      {"flags", statusFlags_->get_hex()},
      {"gid", pi_},
      {"gcgl", "0"},
      {"model", "AudioAccessory6,1"},
      {"pi", pi_},
      {"pk", chars_to_hex(pairingManager_->get_public_key())},
      {"protovers", "1.1"},
      {"rsf", "0x0"},
      {"serialNumber", deviceID_},
      {"srcvers", "366.0"},
  };
  mdns_->publish_service(deviceName_, "_airplay._tcp", 7000, txt);
  return 0;
}

int AirPlayServer::publish_raop_service() {
  std::map<std::string, std::string> txt = {
      // {"pk", crypto_handler_->get_public_hex_string()},
      {"ch", "2"},
      {"cn", "0,1,2"},
      // {"et", "0,4"},
      // {"am", "Linux"},
      // {"tp", "UDP"},
      // {"md", "2"},
      // {"vn", "65537"},
      // {"srcvers", "366.0"},
      {"pi", pi_},
      {"pk", chars_to_hex(pairingManager_->get_public_key())},
      {"pw", "true"},
      // {"da", "true"},
      {"ft", featureFlags_->get_hex()},
      {"sf", statusFlags_->get_hex()},
      // {"deviceid", device_id_},
  };
  mdns_->publish_service(deviceName_, "_raop._tcp", 5000, txt);
  return 0;
}

void AirPlayServer::stop() {
  if (running_) {
    running_ = false;
    if (server_thread_.joinable())
      server_thread_.join();
  }
  if (mdns_)
    mdns_->stop();
}

void AirPlayServer::handle_client(int clientID) {
  std::cout << "Created new RTSP handler for client with ID: " << clientID
            << std::endl
            << "Starting new RTSP parser..." << std::endl;
  auto rtspParser = create_rtsp_parser(clientID, deviceID_, pi_, featureFlags_,
                                       statusFlags_, pairingManager_);
  std::unique_ptr<CipherTransporter> cipherTransporter;

  char buffer[2048] = {0};
  while (rtspParser->is_running()) {
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_read = read(clientID, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
      std::cout << "Client " << clientID << " disconnected." << std::endl;
      break;
    }

    if (!rtspParser->is_verified()) {
      rtspParser->set_msg(buffer, bytes_read);
      rtspParser->parse_message();

      auto [header, body] = rtspParser->get_response();
      u8Vec_t payload(header.begin(), header.end());
      payload.insert(payload.end(), body.begin(), body.end());

      send(clientID, payload.data(), payload.size(), 0);
    } else if (rtspParser->is_verified() && !cipherTransporter) {
      cipherTransporter =
          create_cipher_transporter(rtspParser->get_shared_key());
    }

    if (cipherTransporter) {
      auto decryptResult =
          cipherTransporter->decrypt_frames(buffer, bytes_read);

      std::string decrypted(decryptResult.plaintext.begin(),
                            decryptResult.plaintext.end());

      rtspParser->set_msg((char *)decrypted.c_str(), decrypted.size());
      rtspParser->parse_message();

      auto [header, body] = rtspParser->get_response();
      u8Vec_t payload(header.begin(), header.end());
      payload.insert(payload.end(), body.begin(), body.end());

      auto aad = cipherTransporter->set_aad(payload);
      auto encryptResult = cipherTransporter->encrypt(
          payload, aad, cipherTransporter->get_write_nonce());

      if (encryptResult.success)
        send(clientID, encryptResult.ciphertext.data(),
             encryptResult.ciphertext.size(), 0);
    }
  }
  close(clientID);
  running_ = false;
}
