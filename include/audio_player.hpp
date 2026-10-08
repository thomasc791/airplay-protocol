#pragma once

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <vector>
class AudioPlayer {
public:
  AudioPlayer();
  ~AudioPlayer();

  void push_audio(const std::vector<uint16_t> &pcm);
  std::vector<int16_t> borrow_buffer();
  void queue_ready_buffer(std::vector<int16_t> pcm);
  void return_to_free_pool(std::vector<int16_t> buffer);

private:
  std::queue<std::vector<int16_t>> freeQueue_;
  std::queue<std::vector<int16_t>> readyQueue_;
  std::mutex poolMutex_;
  std::condition_variable freeAvailableCV_;
  std::condition_variable dataAvailableCV_;
  std::thread playbackThread_;
  std::atomic<bool> running_{false};

  void playback_loop();
  void play();
};

std::shared_ptr<AudioPlayer> create_audio_player();
