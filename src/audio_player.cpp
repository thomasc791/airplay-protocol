#include "audio_player.hpp"
#include "utils.hpp"

#include <alsa/asoundlib.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <vector>

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

std::optional<std::vector<int16_t>>
AudioPlayer::borrow_buffer(std::atomic<bool> &cancel) {
  std::unique_lock<std::mutex> lock(poolMutex_);
  freeAvailableCV_.wait(
      lock, [&] { return !freeQueue_.empty() || !running_ || cancel; });

  if (!running_ || cancel) {
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

int AudioPlayer::prepare() {
  int err =
      snd_pcm_open(&pcm_handle_, "plughw:1,0", SND_PCM_STREAM_PLAYBACK, 0);
  if (err < 0) {
    std::cerr << "ALSA Error: Could not open audio device: "
              << snd_strerror(err) << std::endl;
    return err;
  }

  snd_pcm_set_params(pcm_handle_, SND_PCM_FORMAT_S16_LE,
                     SND_PCM_ACCESS_RW_INTERLEAVED, 2, 44100, 1, 500000);

  return err;
}

void AudioPlayer::playback_loop() {
  if (prepare()) {
    return;
  }

  std::ofstream raw("out.raw", std::ios::binary | std::ios::app);

  while (running_) {
    {
      std::unique_lock<std::mutex> lock(poolMutex_);

      dataAvailableCV_.wait(lock, [this] {
        return (!readyQueue_.empty() && !paused_) || !running_;
      });

      if (!running_) {
        break;
      }

      hardwareChunk_ = std::move(readyQueue_.front());
      readyQueue_.pop();
    }

    auto gen = flushGen_.load();
    if (gen != seenGen_) {
      snd_pcm_drop(pcm_handle_);
      snd_pcm_prepare(pcm_handle_);
      seenGen_ = gen;
      hardwareChunk_.clear();
    }
    raw.write(reinterpret_cast<const char *>(hardwareChunk_.data()),
              hardwareChunk_.size());
    play();

    {
      std::lock_guard<std::mutex> lock(poolMutex_);
      hardwareChunk_.clear();
      freeQueue_.push(std::move(hardwareChunk_));
      freeAvailableCV_.notify_one();
    }
  }
  if (pcm_handle_) {
    snd_pcm_drop(pcm_handle_);
    snd_pcm_close(pcm_handle_);
  }
}

void AudioPlayer::pause() {
  std::lock_guard<std::mutex> lock(poolMutex_);
  paused_ = true;

  dataAvailableCV_.notify_all();
}

void AudioPlayer::resume() {
  std::lock_guard<std::mutex> lock(poolMutex_);
  paused_ = false;

  dataAvailableCV_.notify_all();
}

void AudioPlayer::flush(uint16_t untilSeq) {
  {
    std::lock_guard<std::mutex> lock(poolMutex_);
    dropUntilSeq_ = untilSeq;
    drain_ready();
  }

  freeAvailableCV_.notify_all();
}

void AudioPlayer::reset() {
  {
    std::lock_guard<std::mutex> lock(poolMutex_);
    dropUntilSeq_ = -1;
    drain_ready();
  }
  freeAvailableCV_.notify_all();
}

void AudioPlayer::drain_ready() {
  while (!readyQueue_.empty()) {
    auto buffer = std::move(readyQueue_.front());
    readyQueue_.pop();
    buffer.clear();
    freeQueue_.push(std::move(buffer));
  }

  flushGen_++;
}

bool AudioPlayer::should_drop(uint16_t seq) {
  int32_t until = dropUntilSeq_.load();
  if (until < 0) {
    return false;
  }
  if (int16_t(seq - uint16_t(until)) <= 0) {
    return true;
  }
  dropUntilSeq_ = -1;
  return false;
}

void AudioPlayer::wake_waiters() {
  std::lock_guard<std::mutex> lock(poolMutex_);
  freeAvailableCV_.notify_all();
}

void AudioPlayer::play() {
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
      snd_pcm_writei(pcm_handle_, hardwareChunk_.data(), frames);

  if (written < 0) {
    std::cerr << "ALSA Write Failed/Unrecoverable: " << snd_strerror(written)
              << std::endl;
    written = snd_pcm_recover(pcm_handle_, written, 0);
    if (written < 0) {
      std::cerr << "ALSA Unrecoverable: " << snd_strerror(written) << std::endl;
    }
  }
}

std::shared_ptr<AudioPlayer> create_audio_player() {
  return std::make_shared<AudioPlayer>();
}
