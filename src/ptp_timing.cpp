#include "ptp_timing.hpp"
#include "utils.hpp"

#include <memory>

constexpr std::string tag = "PTPHandler";

PTPTimingHandler::PTPTimingHandler() {
  auto callback = [this](const char *data, size_t length, sockaddr_in sender) {
    this->handle_ptp_timing(data, length, sender);
  };
  listener_ = std::make_unique<UDPServer>(callback, "PTPTimingHandler", 0);
}

PTPTimingHandler::~PTPTimingHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void PTPTimingHandler::start() { listener_->start(); };

void PTPTimingHandler::handle_ptp_timing(const char *data, size_t length,
                                         sockaddr_in sender) {
  running_ = listener_->is_running();
  while (running_) {
  }
}

std::unique_ptr<PTPTimingHandler> create_ptp_timing_handler() {
  return std::make_unique<PTPTimingHandler>();
}
