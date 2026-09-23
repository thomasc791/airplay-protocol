#include "ptp_timing.hpp"
#include "utils.hpp"

#include <iostream>
#include <memory>

constexpr std::string tag = "PTPHandler";

PTPTimingHandler::PTPTimingHandler() {
  auto callback = [this](const char *data, size_t length, sockaddr_in sender) {
    this->handle_ptp_timing(data, length, sender);
  };
  listener_ = std::make_unique<UDPServer>(callback, "PTPTimingHandler", 31900);
}

PTPTimingHandler::~PTPTimingHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void PTPTimingHandler::start() { listener_->start(); };

void PTPTimingHandler::handle_ptp_timing(const char *data, size_t length,
                                         sockaddr_in sender) {
  std::cout << "[" << tag << "] Received " << length << " bytes from iPhone!"
            << std::endl;

  // Optional: Print the first byte to see the PTP message type
  printf("[PTP] Message Type: %02x\n", (unsigned char)data[0]);
}

std::unique_ptr<PTPTimingHandler> create_ptp_timing_handler() {
  return std::make_unique<PTPTimingHandler>();
}
