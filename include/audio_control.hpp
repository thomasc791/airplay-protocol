#pragma once

#include "socket.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

class AudioControlHandler {
public:
  AudioControlHandler();
  ~AudioControlHandler();

  uint64_t get_port() { return listener_->get_port(); }

  void start();

private:
  std::unique_ptr<TCPServer> listener_;
  std::atomic<bool> running_{false};

  void handle_events(int clientID);
};

std::unique_ptr<AudioControlHandler> create_audio_control_handler();
