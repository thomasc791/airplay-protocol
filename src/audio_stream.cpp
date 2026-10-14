#include "audio_stream.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstring>
#include <iostream>
#include <unistd.h>

constexpr std::string tag = "AudioHandler";
constexpr size_t BUFFER_SIZE = 0x400000;

AudioDataHandler::AudioDataHandler(
    const std::shared_ptr<AudioPlayer> &audioPlayer, uint64_t format,
    u8Vec_t shk, Protocol protocol)
    : protocol_(protocol), tag_(16), audioPlayer_(audioPlayer), format_(format),
      shk_(shk) {
  switch (protocol_) {
  case Protocol::UDP:
    udpListener_ = std::make_unique<UDPServer>(
        [this](const char *data, size_t length, sockaddr_storage sender) {
          this->handle_udp_data(data, length, sender);
        },
        "AudioDataHandler", 0);
    log_event(tag, "Created UDP Listener");
    break;
  case Protocol::TCP:
    receiveBuffer_.resize(BUFFER_SIZE);
    tcpListener_ = std::make_unique<TCPServer>(
        [this](int id) { this->handle_tcp_data(id); }, "AudioDataHandler", 0,
        timeval{1, 0});
    log_event(tag, "Created TCP Listener");
    break;
  }

  cipher_ = create_cipher_transporter(shk_);
  cipher_->set_decryption_key(shk_);

  audioDecoder_ = create_audio_decoder(format_);
  correctContext_ = audioDecoder_->create_context();
}

AudioDataHandler::~AudioDataHandler() {
  cancel_ = true;

  audioPlayer_->wake_waiters();
  tcpListener_.reset();
  udpListener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioDataHandler::start() {
  switch (protocol_) {
  case Protocol::UDP:
    udpListener_->start();
    break;
  case Protocol::TCP:
    tcpListener_->start();
    break;
  }
};

void AudioDataHandler::handle_tcp_data(int id) {
  running_ = tcpListener_->is_running();

  if (correctContext_ < 0) {
    shutdown(id, SHUT_RDWR);
    close(id);
    return;
  }

  size_t audioSize = 0;

  while (running_) {
    int offset = read_exact_bytes(id, receiveBuffer_, 2, 0);
    if (0 >= offset)
      break;

    uint16_t payload_size = (static_cast<uint16_t>(receiveBuffer_[0]) << 8) |
                            static_cast<uint16_t>(receiveBuffer_[1]);

    if (payload_size < 38) {
      break;
    }

    audioSize = payload_size - 38;

    offset = read_exact_bytes(id, receiveBuffer_, payload_size - 2, 2);
    if (0 >= offset)
      break;

    uint16_t sequence = (static_cast<uint16_t>(receiveBuffer_[4]) << 8 |
                         static_cast<uint16_t>(receiveBuffer_[5]));
    uint32_t timestamp = (static_cast<uint32_t>(receiveBuffer_[6]) << 24 |
                          static_cast<uint32_t>(receiveBuffer_[7]) << 16 |
                          static_cast<uint32_t>(receiveBuffer_[8]) << 8 |
                          static_cast<uint32_t>(receiveBuffer_[9]));

    if (audioPlayer_->should_drop(sequence)) {
      continue;
    }

    std::memcpy(tag_.data(), receiveBuffer_.data() + payload_size - 24, 16);
    std::memcpy(nonce.data() + 4, receiveBuffer_.data() + payload_size - 8, 8);

    cipher_->decrypt(result, receiveBuffer_.data() + 14, audioSize,
                     receiveBuffer_.data() + 6, 8, nonce,
                     receiveBuffer_.data() + payload_size - 24);

    if (!result.success) {
      std::cerr << "Did not decrypt properly" << std::endl;
      continue;
    }

    auto borrowed = audioPlayer_->borrow_buffer(cancel_);
    if (!borrowed)
      break;
    pcm = std::move(*borrowed);
    pcm.clear();

    if (audioDecoder_->play_audio(result.plaintext.data(), result.size, pcm) <
        0) {
      audioPlayer_->return_to_free_pool(std::move(pcm));
      continue;
    }

    audioPlayer_->queue_ready_buffer(std::move(pcm));

    result.plaintext.clear();
  }
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

void AudioDataHandler::handle_udp_data(const char *data, size_t length,
                                       sockaddr_storage) {
  if (correctContext_ < 0) {
    return;
  }

  if (length < 38 || length > BUFFER_SIZE) {
    return;
  }

  uint16_t sequence =
      (static_cast<uint16_t>(data[2]) << 8 | static_cast<uint16_t>(data[3]));
  uint32_t timestamp =
      (static_cast<uint32_t>(data[4]) << 24 |
       static_cast<uint32_t>(data[5]) << 16 |
       static_cast<uint32_t>(data[6]) << 8 | static_cast<uint32_t>(data[7]));

  std::memcpy(tag_.data(), data + length - 24, 16);
  std::memcpy(nonce.data() + 4, data + length - 8, 8);

  int audioSize = length - 36;

  cipher_->decrypt(result, (const uint8_t *)data + 12, audioSize,
                   (const uint8_t *)data + 4, 8, nonce,
                   (const uint8_t *)data + length - 24);

  if (!result.success) {
    std::cerr << "Did not decrypt properly" << std::endl;
    return;
  }

  auto borrowed = audioPlayer_->borrow_buffer(cancel_);
  if (!borrowed)
    return;
  pcm = std::move(*borrowed);
  pcm.clear();

  std::cout << "Sequence: " << sequence << " | Number of bytes: " << result.size
            << std::endl;
  std::cout << "Bytes 0-63" << std::endl;
  for (size_t i = 0; i < 64; i++)
    printf("%02x ", (uint8_t)result.plaintext[i]);
  std::cout << std::endl;

  std::cout << "Bytes 256-287" << std::endl;
  for (size_t i = 256; i < 288; i++)
    printf("%02x ", (uint8_t)result.plaintext[i]);
  std::cout << std::endl;

  if (audioDecoder_->play_audio(result.plaintext.data(), result.size, pcm) <
      0) {
    audioPlayer_->return_to_free_pool(std::move(pcm));
    return;
  }

  audioPlayer_->queue_ready_buffer(std::move(pcm));

  result.plaintext.clear();
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

uint64_t AudioDataHandler::get_port() {
  switch (protocol_) {
  case (Protocol::TCP):
    return tcpListener_->get_port();
    break;
  case (Protocol::UDP):
    return udpListener_->get_port();
    break;
  default:
    return 0;
  }
}

std::shared_ptr<AudioDataHandler>
create_audio_handler(const std::shared_ptr<AudioPlayer> &audioPlayer,
                     uint64_t format, u8Vec_t shk, Protocol protocol) {
  return std::make_shared<AudioDataHandler>(audioPlayer, format, shk, protocol);
}
