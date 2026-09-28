#include "audio_control.hpp"
#include "utils.hpp"

#include <iostream>
#include <memory>

constexpr std::string tag = "EventHandler";

AudioControlHandler::AudioControlHandler(Protocol protocol)
    : protocol_(protocol) {
  switch (protocol) {
  case Protocol::UDP:
    udpListener_ = std::make_unique<UDPServer>(
        [this](const char *data, size_t length, sockaddr_storage sender) {
          this->handle_udp_controls(data, length, sender);
        },
        "AudioControlHandler", 0);
    break;
  case Protocol::TCP:
    tcpListener_ = std::make_unique<TCPServer>(
        [this](int id) { this->handle_tcp_controls(id); },
        "AudioControlHandler", 0, timeval{1, 0});
  }
}

uint64_t AudioControlHandler::get_port() {
  switch (protocol_) {
  case (Protocol::UDP):
    return udpListener_->get_port();
    break;
  case (Protocol::TCP):
    return tcpListener_->get_port();
  }
}

AudioControlHandler::~AudioControlHandler() {
  tcpListener_.reset();
  udpListener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioControlHandler::start() {
  switch (protocol_) {
  case (Protocol::UDP):
    udpListener_->start();
    break;
  case (Protocol::TCP):
    tcpListener_->start();
  }
}

void AudioControlHandler::handle_udp_controls(const char *data, size_t length,
                                              sockaddr_storage sender) {
  running_ = udpListener_->is_running();

  std::cout << "[" << tag << "] Received " << length << " bytes from iPhone!"
            << std::endl;

  printf("[PTP] Message Type: %02x\n", (unsigned char)data[0]);
}

void AudioControlHandler::handle_tcp_controls(int id) {
  running_ = tcpListener_->is_running();

  running_ = tcpListener_->is_running();

  constexpr size_t BUFFER_SIZE = 4096;
  char buffer[BUFFER_SIZE];

  while (running_) {
    ssize_t bytes_read = recv(id, buffer, BUFFER_SIZE, 0);

    if (bytes_read > 0) {
      std::cout << "[" << tag << "]" << std::endl
                << chars_to_hex_c((const uint8_t *)buffer, bytes_read)
                << std::endl;
    } else if (bytes_read == 0) {
      std::cout << "[" << tag << "] TCP Client disconnected." << std::endl;
      break;
    } else {
      break;
    }
  }
}

int get_key(ControlSlotArray streams, size_t key) {
  for (size_t i = 0; i < streams.size(); i++) {
    if (streams[i].active && streams[i].streamID == key) {
      return i;
    }
  }
  return -1;
}

int available_stream(ControlSlotArray streams) {
  for (size_t i = 0; i < streams.size(); i++) {
    if (!streams[i].active) {
      return i;
    }
  }

  return -1;
}

std::shared_ptr<AudioControlHandler>
create_audio_control_handler(Protocol protocol) {
  return std::make_shared<AudioControlHandler>(protocol);
}
