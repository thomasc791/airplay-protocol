#pragma once
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>

template <typename T> class ThreadQueue {
private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable cv_;

public:
  void push(T item) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      queue_.push(std::move(item));
    }
    cv_.notify_one();
  }

  bool pop(T &item, int timeout_ms = -1) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (timeout_ms < 0) {
      cv_.wait(lock, [this] { return !queue_.empty(); });
    } else {
      bool success = cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty(); });
      if (!success)
        return false;
    }
    item = std::move(queue_.front());
    queue_.pop();
    return true;
  }

  size_t size() {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }
};
