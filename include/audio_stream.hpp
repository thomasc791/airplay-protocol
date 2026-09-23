#pragma once

#include "crypto.hpp"
#include "socket.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

class AudioDataHandler {
public:
  AudioDataHandler();
  ~AudioDataHandler();

  uint64_t get_port() { return listener_->get_port(); }

  void start();

private:
  std::unique_ptr<TCPServer> listener_;
  std::atomic<bool> running_{false};

  void handle_audio_data(int id);
  u8Vec_t read_exact_bytes(int fd, size_t exact_amount);
  uint32_t extract_size_from_header(const u8Vec_t &header);
};

std::unique_ptr<AudioDataHandler> create_audio_handler();
