#pragma once

#include "audio_stream.hpp"
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <queue>
#include <vector>

#include <alsa/asoundlib.h>

class AudioPlayer {
public:
  AudioPlayer();
  ~AudioPlayer();

  std::optional<std::vector<int16_t>> borrow_buffer(std::atomic<bool> &cancel);
  void stop();

  void flush(uint16_t untilSeq);
  void reset();
  void pause();
  void resume();
  void wake_waiters();

  void set_flush(uint16_t untilSeq) { dropUntilSeq_ = untilSeq; }
  bool should_drop(uint16_t seq);

  void queue_ready_buffer(std::vector<int16_t> pcm);
  void return_to_free_pool(std::vector<int16_t> buffer);

private:
  std::queue<std::vector<int16_t>> freeQueue_;
  std::queue<std::vector<int16_t>> readyQueue_;

  std::map<uint16_t, AudioFrame> jitterBuffer_;

  std::mutex poolMutex_;
  std::condition_variable freeAvailableCV_;
  std::condition_variable dataAvailableCV_;
  std::thread playbackThread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> paused_{false};

  std::atomic<int32_t> dropUntilSeq_{-1};
  std::atomic<uint32_t> flushGen_;
  uint32_t seenGen_;
  std::vector<int16_t> hardwareChunk_;

  snd_pcm_t *pcm_handle_ = nullptr;
  snd_mixer_t *mixer_;

  uint64_t audioFormat_;

  int prepare();
  void playback_loop();
  void play();

  void drain_ready();
};

std::shared_ptr<AudioPlayer> create_audio_player();
