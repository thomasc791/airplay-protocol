#pragma once

#include "crypto.hpp"
#include "socket.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

#define MAX_STREAMS 10

class AudioDataHandler {
public:
  AudioDataHandler(u8Vec_t shk);
  ~AudioDataHandler();

  uint64_t get_port() { return listener_->get_port(); }

  void start();

private:
  std::unique_ptr<TCPServer> listener_;
  std::atomic<bool> running_{false};
  u8Vec_t shk_;

  void handle_audio_data(int id);
  u8Vec_t read_exact_bytes(int fd, size_t exact_amount);
  uint32_t extract_size_from_header(const u8Vec_t &header);
};

std::shared_ptr<AudioDataHandler> create_audio_handler(u8Vec_t shk);

struct StreamSlot {
  uint64_t streamID = -1;
  bool active = false;
  std::shared_ptr<AudioDataHandler> stream;

  int reset() {
    this->stream.reset();
    this->active = false;
    this->streamID = -1;

    return this->stream ? -1 : 1;
  }
  std::shared_ptr<AudioDataHandler> &create(uint64_t id, u8Vec_t shk) {
    stream = create_audio_handler(shk);
    stream->start();
    active = true;
    streamID = id;

    return this->stream;
  }
};

typedef std::array<StreamSlot, MAX_STREAMS> StreamSlotArray;

int get_key(StreamSlotArray streams, size_t key);
int available_stream(StreamSlotArray streams);
