#pragma once

#include "crypto.hpp"
#include "socket.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

#define MAX_STREAMS 5

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

std::shared_ptr<AudioDataHandler> create_audio_handler();

struct StreamSlot {
  uint64_t streamID;
  bool active = false;
  std::shared_ptr<AudioDataHandler> stream;

  int reset() {
    this->stream.reset();
    this->active = false;
    this->streamID = 0;

    return this->stream ? -1 : 1;
  }
  std::shared_ptr<AudioDataHandler> &create(uint64_t id) {
    this->stream = create_audio_handler();
    this->stream->start();
    this->active = true;
    this->streamID = id;

    return this->stream;
  }
};

typedef std::array<StreamSlot, MAX_STREAMS> StreamSlotArray;

int get_key(StreamSlotArray streams, size_t key);
int available_stream(StreamSlotArray streams);
