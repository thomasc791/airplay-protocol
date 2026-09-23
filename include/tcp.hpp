#pragma once

#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <thread>

class TcpListener {
public:
  TcpListener(std::function<void(int)> handler) : handler_(handler) {}
  ~TcpListener();

  bool start(uint64_t requested_port, std::string tag);
  uint64_t get_port() const { return port_; }

private:
  std::function<void(int)> handler_;
  std::thread server_thread_;
  std::atomic<bool> running_{false};
  uint64_t port_{0};

  std::string tag;

  void stop();
};

void create_and_bind_socket(
    std::function<void(int)> handler, std::string tag, uint64_t port,
    std::atomic<bool> &running,
    std::shared_ptr<std::promise<uint64_t>> promise_port = nullptr);
