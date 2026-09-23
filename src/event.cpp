#include "event.hpp"

#include <memory>

EventHandler::EventHandler() {
  auto callback = [this](int id) { this->handle_events(id); };
  listener_ = std::make_unique<TcpListener>(callback);
}

EventHandler::~EventHandler() {}

void EventHandler::handle_events(int id) {}

std::unique_ptr<EventHandler> create_event_handler() {
  return std::make_unique<EventHandler>();
}
