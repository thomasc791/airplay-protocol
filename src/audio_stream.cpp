#include "audio_stream.hpp"
#include "audio_decoder.hpp"
#include "crypto.hpp"
#include "transport_crypto.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <unistd.h>

#include <sys/socket.h>

constexpr std::string tag = "AudioHandler";

AudioDataHandler::AudioDataHandler(
    const std::shared_ptr<AudioPlayer> &audioPlayer, uint64_t format,
    u8Vec_t shk)
    : audioPlayer_(audioPlayer), format_(format), shk_(shk) {
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

  auto audioDecoder = create_audio_decoder(format_);
  if (audioDecoder->create_context() < 0) {
    shutdown(id, SHUT_RDWR);
    close(id);
    return;
  }

  DecryptionResult result;
  std::vector<int16_t> pcm;
  std::ofstream raw("out.raw", std::ios::binary | std::ios::app);

  constexpr size_t BUFFER_SIZE = 32768;
  u8Vec_t receiveBuffer(BUFFER_SIZE);
  u8Vec_t tag(16);
  std::array<uint8_t, 12> nonce = {0};

  size_t audioSize = 0;

  while (running_) {
    running_ = listener_->is_running();

    int offset = read_exact_bytes(id, receiveBuffer, 2, 0);
    if (0 >= offset)
      break;

    uint16_t payload_size = (static_cast<uint16_t>(receiveBuffer[0]) << 8) |
                            static_cast<uint16_t>(receiveBuffer[1]);

    if (payload_size < 38 || payload_size > BUFFER_SIZE) {
      break;
    }

    audioSize = payload_size - 38;

    offset = read_exact_bytes(id, receiveBuffer, payload_size - 2, 2);
    if (0 >= offset)
      break;

    uint16_t sequence = (static_cast<uint16_t>(receiveBuffer[4]) << 8 |
                         static_cast<uint16_t>(receiveBuffer[5]));
    uint32_t timestamp = (static_cast<uint32_t>(receiveBuffer[6]) << 24 |
                          static_cast<uint32_t>(receiveBuffer[7]) << 16 |
                          static_cast<uint32_t>(receiveBuffer[8]) << 8 |
                          static_cast<uint32_t>(receiveBuffer[9]));

    std::memcpy(tag.data(), receiveBuffer.data() + payload_size - 24, 16);
    std::memcpy(nonce.data() + 4, receiveBuffer.data() + payload_size - 8, 8);

    cipher->decrypt(result, receiveBuffer.data() + 14, audioSize,
                    receiveBuffer.data() + 6, 8, nonce,
                    receiveBuffer.data() + payload_size - 24);

    if (!result.success) {
      std::cerr << "Did not decrypt properly" << std::endl;
      continue;
    }

    pcm = audioPlayer_->borrow_buffer();
    pcm.clear();
    if (audioDecoder->play_audio(result.plaintext.data(), result.size, pcm) <
        0) {
      audioPlayer_->return_to_free_pool(std::move(pcm));
      continue;
    }

    audioPlayer_->queue_ready_buffer(std::move(pcm));

    result.plaintext.clear();
  }
  shutdown(id, SHUT_RDWR);
  close(id);
}

int AudioDataHandler::read_exact_bytes(int fd, u8Vec_t &recvBuffer,
                                       size_t exact_amount, size_t offset) {
  size_t total_read = 0;

  while (total_read < exact_amount) {
    int bytes = recv(fd, recvBuffer.data() + offset + total_read,
                     exact_amount - total_read, 0);

    if (bytes > 0) {
      total_read += bytes;
    } else if (bytes == 0) {
      return 0;
    } else {
      return -1;
    }
  }
  return 1;
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

std::shared_ptr<AudioDataHandler>
create_audio_handler(const std::shared_ptr<AudioPlayer> &audioPlayer,
                     uint64_t format, u8Vec_t shk) {
  return std::make_shared<AudioDataHandler>(audioPlayer, format, shk);
}
