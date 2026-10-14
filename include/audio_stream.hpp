#pragma once

#include "audio_decoder.hpp"
#include "audio_player.hpp"
#include "crypto.hpp"
#include "socket.hpp"
#include "transport_crypto.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

#define MAX_STREAMS 10

class AudioDataHandler {
public:
  AudioDataHandler(const std::shared_ptr<AudioPlayer> &audioPlayer,
                   uint64_t format, u8Vec_t shk, Protocol protocol);
  ~AudioDataHandler();

  uint64_t get_port();

  void start();

private:
  Protocol protocol_;
  std::unique_ptr<TCPServer> tcpListener_;
  std::unique_ptr<UDPServer> udpListener_;
  std::atomic<bool> running_{false};
  std::atomic<bool> cancel_{false};

  std::unique_ptr<CipherTransporter> cipher_;
  std::unique_ptr<AudioDecoder> audioDecoder_;

  std::shared_ptr<AudioPlayer> audioPlayer_;

  uint64_t format_;
  u8Vec_t shk_;

  void handle_tcp_data(int id);
  void handle_udp_data(const char *data, size_t length,
                       sockaddr_storage sender);
  int read_exact_bytes(int fd, u8Vec_t &recvBuffer, size_t exact_amount,
                       size_t offset);
  uint32_t extract_size_from_header(const u8Vec_t &header);
};

std::shared_ptr<AudioDataHandler>
create_audio_handler(const std::shared_ptr<AudioPlayer> &audioPlayer_,
                     uint64_t format, u8Vec_t shk, Protocol protocol);

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
  std::shared_ptr<AudioDataHandler> &
  create(const std::shared_ptr<AudioPlayer> &audioPlayer, uint64_t id,
         uint64_t format, u8Vec_t shk, Protocol protocol) {
    stream = create_audio_handler(audioPlayer, format, shk, protocol);
    stream->start();
    active = true;
    streamID = id;

    return this->stream;
  }
};

typedef std::array<StreamSlot, MAX_STREAMS> StreamSlotArray;

int get_key(StreamSlotArray streams, size_t key);
int available_stream(StreamSlotArray streams);
