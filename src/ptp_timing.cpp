#include "ptp_timing.hpp"

#include <memory>

PTPTimingHandler::PTPTimingHandler() {
  auto callback = [this](int id) { this->handle_ptp_timing(id); };
  listener_ = std::make_unique<TcpListener>(callback);
}

PTPTimingHandler::~PTPTimingHandler() {}

void PTPTimingHandler::handle_ptp_timing(int id) {}

std::unique_ptr<PTPTimingHandler> create_ptp_timing_handler() {
  return std::make_unique<PTPTimingHandler>();
}
