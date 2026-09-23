#pragma once

#include "tcp.hpp"

#include <cstdint>
#include <memory>

class EventHandler {
public:
  EventHandler();
  ~EventHandler();

  uint64_t get_port() { return listener_->get_port(); }

  bool start() { return listener_->start(0, "EventHandler"); };

private:
  std::unique_ptr<TcpListener> listener_;

  void handle_events(int clientID);
};

std::unique_ptr<EventHandler> create_event_handler();
