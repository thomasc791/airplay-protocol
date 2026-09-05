#include "airplay_server.hpp"
#include "crypto.hpp"
#include "flags.hpp"
#include "pairing-manager.hpp"
#include "rtsp.hpp"
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

  running_ = true;
  server_thread_ = std::thread(&AirPlayServer::run, this);
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

void AirPlayServer::run() {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "[AirPlayServer] Socket creation failed!" << std::endl;
    return;
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port_);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    std::cerr << "[AirPlayServer] Bind failed!" << std::endl;
    close(server_fd);
    return;
  }

  if (listen(server_fd, 5) < 0) {
    std::cerr << "[AirPlayServer] Listen failed!" << std::endl;
    close(server_fd);
    return;
  }

  std::cout << "[AirPlayServer] Listening for iOS connections on port " << port_
            << "..." << std::endl;

  while (running_) {
    sockaddr_in client_addr{};
    socklen_t addrlen = sizeof(client_addr);

    // Simple select to make socket non-blocking for clean shutdown
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int activity = select(server_fd + 1, &readfds, nullptr, nullptr, &timeout);
    if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
      int client_fd =
          accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
      if (client_fd >= 0) {
        std::cout << "[AirPlayServer] New client connected!" << std::endl;
        std::thread(&AirPlayServer::handle_client, this, client_fd).detach();
      }
    }
  }

  close(server_fd);
}

void AirPlayServer::handle_client(int clientID) {
  std::cout << "Created new RTSP handler for client with ID: " << clientID
            << std::endl
            << "Starting new RTSP parser..." << std::endl;
  auto rtspParser = create_rtsp_parser(clientID, deviceID_, pi_, featureFlags_,
                                       statusFlags_, pairingManager_);
  std::unique_ptr<CipherTransporter> cipherTransporter;

  char buffer[2048] = {0};
  while (running_) {
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_read = read(clientID, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
      std::cout << "Client " << clientID << " disconnected." << std::endl;
      break;
    }

    rtspParser->set_msg(buffer, bytes_read);
    if (!verified_) {
      rtspParser->parse_message();
      verified_ = rtspParser->is_verified();
    } else if (verified_ && !cipherTransporter) {
      cipherTransporter =
          create_cipher_transporter(rtspParser->get_shared_key());
    }
    if (cipherTransporter) {
      cipherTransporter->set_message(buffer, bytes_read);
      cipherTransporter->cipher_length();
      // cipherTransporter->set_message(buffer, bytes_read);
      auto [cipher, tag] = get_cipher_tag(cipherTransporter->get_cipher());
      auto nonce = cipherTransporter->get_read_nonce();
      cipherTransporter->decrypt(cipher, nonce, tag);
      // auto decodedBlob = cipherTransporter->get_decoded_str();
      // rtspParser->set_msg(decodedBlob.data(), decodedBlob.size());
    }
  }
  close(clientID);
}
