#pragma once

#include "crypto.hpp"
#include "flags.hpp"
#include "hal/mdns_service.hpp"

#include "rtsp.hpp"
#include <atomic>
#include <memory>
#include <string>
#include <thread>

class AirPlayServer {
private:
  uint16_t port_;
  std::string deviceName_;
  std::string device_id_;
  std::atomic<bool> running_{false};
  std::thread server_thread_;
  std::unique_ptr<IMDnsService> mdns_;
  std::unique_ptr<RTSPParser> rtspParser_;
  std::shared_ptr<CryptoHandler> cryptoHandler_;
  std::shared_ptr<FeatureFlags> featureFlags_;
  std::shared_ptr<StatusFlags> statusFlags_;

  void run();
  int create_airplay_service();
  int publish_airplay_service();
  int publish_raop_service();
  void handle_client(int client_fd);

public:
  AirPlayServer(const std::string &device_name = "Portable AirPlay Receiver",
                uint16_t port = 7000);
  ~AirPlayServer();

  bool start();
  void stop();
};

std::string get_system_mac_address();
