#pragma once

#include <cstdint>
#include <functional>
#include <future>
#include <ifaddrs.h>
#include <memory>
#include <thread>

class SocketResource {
public:
  SocketResource(std::function<void(int)> handler, __socket_type socketType)
      : handler_(handler), socketType_(socketType) {}
  ~SocketResource();

  bool start(uint64_t requested_port, std::string tag);
  uint64_t get_port() const { return port_; }
  bool is_running() { return running_; }

private:
  std::function<void(int)> handler_;
  std::thread server_thread_;
  std::atomic<bool> running_{false};
  __socket_type socketType_;
  uint64_t port_{0};

  std::string tag_;

  void stop();
};

void create_and_bind_socket(
    std::function<void(int)> handler, std::string tag, uint64_t port,
    std::atomic<bool> &running, __socket_type socketType,
    std::shared_ptr<std::promise<uint64_t>> promise_port = nullptr);
