#include "event.hpp"
#include "utils.hpp"

#include <memory>

constexpr std::string tag = "EventHandler";

EventHandler::EventHandler() {
  auto callback = [this](int id) { this->handle_events(id); };
  listener_ = std::make_unique<TCPServer>(callback, "EventHandler", 31901);
}

EventHandler::~EventHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void EventHandler::start() { listener_->start(); };

void EventHandler::handle_events(int id) {
  running_ = listener_->is_running();
  while (running_) {
  }
}

std::unique_ptr<EventHandler> create_event_handler() {
  return std::make_unique<EventHandler>();
}
