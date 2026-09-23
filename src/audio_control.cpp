#include "audio_control.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <memory>

constexpr std::string tag = "EventHandler";

AudioControlHandler::AudioControlHandler() {
  auto callback = [this](const char *data, size_t length, sockaddr_in sender) {
    this->handle_controls(data, length, sender);
  };
  listener_ = std::make_unique<UDPServer>(callback, "AudioControlHandler", 0);
}

AudioControlHandler::~AudioControlHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioControlHandler::start() { listener_->start(); };

void AudioControlHandler::handle_controls(const char *data, size_t length,
                                          sockaddr_in sender) {
  running_ = listener_->is_running();

  while (running_) {
  }
}

std::unique_ptr<AudioControlHandler> create_audio_control_handler() {
  return std::make_unique<AudioControlHandler>();
}
