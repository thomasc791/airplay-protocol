#pragma once

#include "socket.hpp"

#include <cstdint>
#include <memory>

class PTPTimingHandler {
public:
  PTPTimingHandler();
  ~PTPTimingHandler();

  uint64_t get_port() { return listener_->get_port(); }

  void start();

private:
  std::unique_ptr<UDPServer> listener_;
  std::atomic<bool> running_{false};

  void handle_ptp_timing(const char *data, size_t length, sockaddr_in sender);
};

std::unique_ptr<PTPTimingHandler> create_ptp_timing_handler();
