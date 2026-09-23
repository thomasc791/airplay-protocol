#include "audio_stream.hpp"
#include "utils.hpp"

#include <memory>
#include <sys/socket.h>

constexpr std::string tag = "AudioHandler";

AudioHandler::AudioHandler() {
  auto callback = [this](const char *data, size_t length, sockaddr_in sender) {
    this->handle_events(data, length, sender);
  };
  listener_ = std::make_unique<UDPServer>(callback, "AudioHandler", 0);
}

AudioHandler::~AudioHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioHandler::start() { listener_->start(); };

void AudioHandler::handle_events(const char *data, size_t length,
                                 sockaddr_in sender) {
  running_ = listener_->is_running();
  while (running_) {
  }
}

std::unique_ptr<AudioHandler> create_audio_handler() {
  return std::make_unique<AudioHandler>();
}
