#include "event.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <iostream>
#include <memory>

constexpr std::string tag = "EventHandler";

EventHandler::EventHandler() {
  auto callback = [this](int id) { this->handle_events(id); };
  listener_ = std::make_unique<TCPServer>(callback, "EventHandler", 0);
}

EventHandler::~EventHandler() {
  running_ = false;
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void EventHandler::start() { listener_->start(); };

void EventHandler::handle_events(int fd) {
  running_ = listener_->is_running();
  u8Vec_t buffer(2048);
  while (running_) {
    int bytes = recv(fd, buffer.data(), 2048, 0);
    std::cout << "Read bytes: " << bytes << std::endl;
    log_event(tag, (const char *)buffer.data());
  }
}

std::unique_ptr<EventHandler> create_event_handler() {
  return std::make_unique<EventHandler>();
}
