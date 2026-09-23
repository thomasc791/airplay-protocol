#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <thread>

class SocketResource {
public:
  SocketResource(__socket_type socketType, uint64_t port);
  ~SocketResource();

  bool start(std::string tag);
  void stop();

  uint64_t get_port() const { return port_; }
  bool is_running() const { return running_; }
  int get_fd() const { return fd_; }

private:
  int fd_;
  std::thread server_thread_;
  std::atomic<bool> running_{false};
  __socket_type socketType_;
  uint64_t port_{0};

  std::string tag_;
};

class TCPServer {
public:
  TCPServer(std::function<void(int)> handler, std::string tag = "TCPServer",
            uint64_t port = 0);
  ~TCPServer();

  uint64_t get_port() { return socket_->get_port(); }
  bool is_running() { return socket_->is_running(); }
  bool start();

private:
  int fd_;

  std::thread loopThread_;
  std::string tag_;
  std::function<void(int)> handler_;
  std::unique_ptr<SocketResource> socket_;

  void server_loop();
};

class UDPServer {
public:
  UDPServer(
      std::function<void(const char *data, size_t length, sockaddr_in sender)>
          handler,
      std::string tag = "UDPServer", uint64_t port = 0);

  uint64_t get_port() { return socket_->get_port(); }
  bool is_running() { return socket_->is_running(); }
  bool start();

private:
  int fd_;
  std::string tag_;
  std::function<void(const char *data, size_t length, sockaddr_in sender)>
      handler_;
  std::unique_ptr<SocketResource> socket_;

  void server_loop();
};
