#pragma once

#include "socket.hpp"
#include <memory>
class CaptivePortal {
public:
  CaptivePortal();
  ~CaptivePortal();

  void start();
  void stop();

  void set_ssid_options(std::vector<std::string> options) {
    ssidOptions_ = options;
  }

private:
  std::unique_ptr<TCPServer> httpServer_;
  std::vector<std::string> ssidOptions_;

  void handle_http_client(int client_fd);
};
