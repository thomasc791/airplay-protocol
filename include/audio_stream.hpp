#pragma once

#include "socket.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

class AudioHandler {
public:
  AudioHandler();
  ~AudioHandler();

  uint64_t get_port() { return listener_->get_port(); }

  void start();

private:
  std::unique_ptr<UDPServer> listener_;
  std::atomic<bool> running_{false};

  void handle_events(const char *data, size_t length, sockaddr_in sender);
};

std::unique_ptr<AudioHandler> create_audio_handler();
