#include "audio_player.hpp"
#include "utils.hpp"

#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <vector>

#include <alsa/asoundlib.h>

constexpr std::string tag = "AudioPlayer";

AudioPlayer::AudioPlayer() {
  for (size_t i = 0; i < 10; i++) {
    std::vector<int16_t> buffer(8192, 0);
    freeQueue_.push(std::move(buffer));
  }

  running_ = true;
  playbackThread_ = std::thread([this]() { this->playback_loop(); });
}

void AudioPlayer::stop() {
  {
    std::lock_guard<std::mutex> lock(poolMutex_);
    running_ = false;
  }
  dataAvailableCV_.notify_all();
  freeAvailableCV_.notify_all();
}

AudioPlayer::~AudioPlayer() {
  stop();

  if (playbackThread_.joinable()) {
    playbackThread_.join();
  }
  log_event(tag, "Deleted handler.");
}

std::optional<std::vector<int16_t>> AudioPlayer::borrow_buffer() {
  std::unique_lock<std::mutex> lock(poolMutex_);
  freeAvailableCV_.wait(lock,
                        [this] { return !freeQueue_.empty() || !running_; });

  if (!running_) {
    return std::nullopt;
  }

  auto buffer = std::move(freeQueue_.front());
  freeQueue_.pop();

  return buffer;
}

void AudioPlayer::return_to_free_pool(std::vector<int16_t> buffer) {
  std::lock_guard<std::mutex> lock(poolMutex_);
  buffer.clear();
  freeQueue_.push(std::move(buffer));
  freeAvailableCV_.notify_one();
}

void AudioPlayer::queue_ready_buffer(std::vector<int16_t> pcm) {
  std::lock_guard<std::mutex> lock(poolMutex_);
  readyQueue_.push(std::move(pcm));
  dataAvailableCV_.notify_one();
}

void AudioPlayer::playback_loop() {
  snd_pcm_t *pcm_handle = nullptr;
  int err = snd_pcm_open(&pcm_handle, "plughw:1,0", SND_PCM_STREAM_PLAYBACK, 0);
  if (err < 0) {
    std::cerr << "ALSA Error: Could not open audio device: "
              << snd_strerror(err) << std::endl;
    return;
  }

  snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE,
                     SND_PCM_ACCESS_RW_INTERLEAVED, 2, 44100, 1, 500000);

  while (running_) {
    std::vector<int16_t> hardwareChunk_;

    {
      std::unique_lock<std::mutex> lock(poolMutex_);
      dataAvailableCV_.wait(
          lock, [this] { return !readyQueue_.empty() || !running_; });

      if (!running_) {
        break;
      }

      hardwareChunk_ = std::move(readyQueue_.front());
      readyQueue_.pop();
    }

    long signal_sum = 0;
    for (size_t i = 0; i < std::min<size_t>(100, hardwareChunk_.size()); ++i) {
      signal_sum += std::abs(hardwareChunk_[i]);
    }

    if (signal_sum == 0) {
      std::cout << "Warning: ALSA received absolute silence (0 variance)."
                << std::endl;
    }

    int frames = hardwareChunk_.size() / 2;
    snd_pcm_sframes_t written =
        snd_pcm_writei(pcm_handle, hardwareChunk_.data(), frames);

    if (written < 0) {
      written = snd_pcm_recover(pcm_handle, written, 0);
      if (written < 0) {
        std::cerr << "ALSA Write Failed/Unrecoverable: "
                  << snd_strerror(written) << std::endl;
      }
    }

    {
      std::lock_guard<std::mutex> lock(poolMutex_);
      hardwareChunk_.clear();
      freeQueue_.push(std::move(hardwareChunk_));
      freeAvailableCV_.notify_one();
    }
  }
  if (pcm_handle) {
    snd_pcm_drop(pcm_handle);
    snd_pcm_close(pcm_handle);
  }
}

void AudioPlayer::play() {}

std::shared_ptr<AudioPlayer> create_audio_player() {
  return std::make_shared<AudioPlayer>();
}
