#pragma once

#include "socket.hpp"
#include <condition_variable>
#include <memory>

struct Credentials {
  std::string ssid;
  std::string password;
};

class CaptivePortal {
public:
  CaptivePortal();
  ~CaptivePortal();

  void start();
  void stop();

  std::optional<Credentials> wait_for_credentials(std::chrono::milliseconds t);

  void set_ssid_options(std::vector<std::string> options) {
    ssidOptions_ = options;
  }

private:
  std::unique_ptr<TCPServer> httpServer_;
  std::vector<std::string> ssidOptions_;

  std::mutex credMutex_;
  std::optional<Credentials> creds_;
  std::condition_variable credCV_;

  void handle_http_client(int client_fd);
};
