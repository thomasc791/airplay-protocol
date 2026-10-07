#include "audio_stream.hpp"
#include "crypto.hpp"
#include "transport_crypto.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

constexpr std::string tag = "AudioHandler";

AudioDataHandler::AudioDataHandler(u8Vec_t shk) : shk_(shk) {
  auto callback = [this](int id) { this->handle_audio_data(id); };
  listener_ = std::make_unique<TCPServer>(callback, "AudioDataHandler", 0);
}

AudioDataHandler::~AudioDataHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioDataHandler::start() { listener_->start(); };

void AudioDataHandler::handle_audio_data(int id) {
  running_ = listener_->is_running();

  auto cipher = create_cipher_transporter(shk_);
  cipher->set_decryption_key(shk_);

  DecryptionResult result;

  constexpr size_t BUFFER_SIZE = 32768;
  u8Vec_t receiveBuffer(BUFFER_SIZE);
  u8Vec_t tag(16);
  std::array<uint8_t, 12> nonce = {0};

  size_t audioSize = 0;

  while (running_) {
    read_exact_bytes(id, receiveBuffer, 2, 0);

    uint16_t payload_size = (static_cast<uint16_t>(receiveBuffer[0]) << 8) |
                            static_cast<uint16_t>(receiveBuffer[1]);

    audioSize = payload_size - 38;

    size_t encryptAudioOffset =
        read_exact_bytes(id, receiveBuffer, payload_size - 2, 2);

    if (2 != encryptAudioOffset)
      break;

    std::memcpy(tag.data(), receiveBuffer.data() + payload_size - 24, 16);
    std::memcpy(nonce.data() + 4, receiveBuffer.data() + payload_size - 8, 8);

    auto plainText = cipher->decrypt(
        result, receiveBuffer.data() + 14, audioSize, receiveBuffer.data() + 6,
        8, nonce, receiveBuffer.data() + payload_size - 24);

    std::cout << chars_to_hex(
                     u8Vec_t(receiveBuffer.begin(), receiveBuffer.begin() + 2))
              << std::endl;
    std::cout << chars_to_hex(u8Vec_t(receiveBuffer.begin() + 2,
                                      receiveBuffer.begin() + 10))
              << std::endl;
    // }
  }
  shutdown(id, SHUT_RDWR);
  close(id);
}

size_t AudioDataHandler::read_exact_bytes(int fd, u8Vec_t &recvBuffer,
                                          size_t exact_amount, size_t offset) {
  size_t total_read = 0;

  while (total_read < exact_amount) {
    ssize_t bytes = recv(fd, recvBuffer.data() + offset + total_read,
                         exact_amount - total_read, 0);

    if (bytes > 0) {
      total_read += bytes;
    } else if (bytes == 0) {
      return {};
    } else {
      return {};
    }
  }
  return offset;
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

int get_key(StreamSlotArray streams, size_t key) {
  for (size_t i = 0; i < streams.size(); i++) {
    if (streams[i].active && streams[i].streamID == key) {
      return i;
    }
  }
  return -1;
}

int available_stream(StreamSlotArray streams) {
  for (size_t i = 0; i < streams.size(); i++) {
    if (!streams[i].active) {
      return i;
    }
  }

  return -1;
}

std::shared_ptr<AudioDataHandler> create_audio_handler(u8Vec_t shk) {
  return std::make_shared<AudioDataHandler>(shk);
}
