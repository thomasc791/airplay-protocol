#include "audio_control.hpp"
#include "utils.hpp"

#include <memory>

constexpr std::string tag = "EventHandler";

AudioControlHandler::AudioControlHandler() {
  auto callback = [this](int id) { this->handle_events(id); };
  listener_ = std::make_unique<TCPServer>(callback, "AudioControlHandler", 0);
}

AudioControlHandler::~AudioControlHandler() {
  listener_.reset();
  log_event(tag, "Deleting handler.");
}

void AudioControlHandler::start() { listener_->start(); };

void AudioControlHandler::handle_events(int id) {
  running_ = listener_->is_running();
  while (running_) {
  }
}

std::unique_ptr<AudioControlHandler> create_audio_control_handler() {
  return std::make_unique<AudioControlHandler>();
}
