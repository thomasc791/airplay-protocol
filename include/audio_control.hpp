#pragma once

#include "audio_stream.hpp"
#include "socket.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

enum class Protocol { UDP, TCP };

class AudioControlHandler {
public:
  AudioControlHandler(Protocol protocol);
  ~AudioControlHandler();

  uint64_t get_port();

  void start();

private:
  Protocol protocol_;
  std::unique_ptr<UDPServer> udpListener_;
  std::unique_ptr<TCPServer> tcpListener_;
  std::atomic<bool> running_{false};

  void handle_udp_controls(const char *data, size_t length,
                           sockaddr_storage sender);
  void handle_tcp_controls(int id);
};

std::shared_ptr<AudioControlHandler>
create_audio_control_handler(Protocol protocol);

struct ControlSlot {
  uint64_t streamID = -1;
  bool active = false;
  std::shared_ptr<AudioControlHandler> stream;

  int reset() {
    this->stream.reset();
    this->active = false;
    this->streamID = -1;

    return this->stream ? -1 : 1;
  }
  std::shared_ptr<AudioControlHandler> &create(Protocol protocol, uint64_t id) {
    this->stream = create_audio_control_handler(protocol);
    this->stream->start();
    this->active = true;
    this->streamID = id;

    return this->stream;
  }
};

typedef std::array<ControlSlot, MAX_STREAMS> ControlSlotArray;

int get_key(ControlSlotArray streams, size_t key);
int available_stream(ControlSlotArray streams);
