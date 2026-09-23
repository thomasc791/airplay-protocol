#include "audio_stream.hpp"
#include "utils.hpp"

#include <memory>
#include <sys/socket.h>

constexpr std::string tag = "AudioHandler";

AudioDataHandler::AudioDataHandler() {
  auto callback = [this](int id) { this->handle_audio_data(id); };
  listener_ = std::make_unique<TCPServer>(callback, "AudioControlHandler", 0);
}

AudioDataHandler::~AudioDataHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioDataHandler::start() { listener_->start(); };

void AudioDataHandler::handle_audio_data(int id) {
  running_ = listener_->is_running();

  constexpr size_t BUFFER_SIZE = 32768;
  u8Vec_t recv_buffer(BUFFER_SIZE);

  while (running_) {
    std::vector<uint8_t> header_data = read_exact_bytes(id, 4);
    if (header_data.empty())
      break;

    uint32_t payload_size = extract_size_from_header(header_data);

    u8Vec_t encrypted_audio = read_exact_bytes(id, payload_size);
    if (encrypted_audio.empty())
      break;
  }
}

u8Vec_t AudioDataHandler::read_exact_bytes(int fd, size_t exact_amount) {
  std::vector<uint8_t> buffer(exact_amount);
  size_t total_read = 0;

  while (total_read < exact_amount) {
    ssize_t bytes =
        recv(fd, buffer.data() + total_read, exact_amount - total_read, 0);

    if (bytes > 0) {
      total_read += bytes;
    } else if (bytes == 0) {
      return {};
    } else {
      return {};
    }
  }
  return buffer;
}

uint32_t AudioDataHandler::extract_size_from_header(const u8Vec_t &header) {
  if (header.size() < 4)
    return 0;

  uint32_t payload_size = (static_cast<uint32_t>(header[0]) << 24) |
                          (static_cast<uint32_t>(header[1]) << 16) |
                          (static_cast<uint32_t>(header[2]) << 8) |
                          static_cast<uint32_t>(header[3]);

  return payload_size;
}

std::unique_ptr<AudioDataHandler> create_audio_handler() {
  return std::make_unique<AudioDataHandler>();
}
