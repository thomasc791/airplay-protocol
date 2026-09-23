#pragma once

#include "tcp.hpp"

#include <cstdint>
#include <memory>

class PTPTimingHandler {
public:
  PTPTimingHandler();
  ~PTPTimingHandler();

  uint64_t get_port() { return listener_->get_port(); }

  bool start() { return listener_->start(0, "PTPTimingHandler"); };

private:
  std::unique_ptr<TcpListener> listener_;

  void handle_ptp_timing(int clientID);
};

std::unique_ptr<PTPTimingHandler> create_ptp_timing_handler();
