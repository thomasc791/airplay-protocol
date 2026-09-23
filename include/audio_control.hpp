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
  std::unique_ptr<UDPServer> listener_;
  std::atomic<bool> running_{false};

  void handle_controls(const char *data, size_t length, sockaddr_in sender);
};

std::unique_ptr<AudioControlHandler> create_audio_control_handler();
