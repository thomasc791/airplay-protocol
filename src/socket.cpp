#include "socket.hpp"
#include "utils.hpp"

#include <cstdint>
#include <ifaddrs.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sys/socket.h>
#include <unistd.h>

SocketResource::SocketResource(__socket_type socketType, uint64_t port)
    : fd_(-1), socketType_(socketType), port_(port) {}

SocketResource::~SocketResource() {
  running_ = false;
  stop();
  log_event(tag_, "Deleting socket.");
}

bool SocketResource::start(std::string tag) {
  tag_ = tag;
  running_ = true;

  int fd = socket(AF_INET6, socketType_, 0);
  if (fd < 0)
    return false;

  int opt_reuse = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(opt_reuse));

  // Force the socket to be Dual-Stack (Accept IPv4 and IPv6)
  int opt_v6only = 0;
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt_v6only,
                 sizeof(opt_v6only)) < 0) {
    std::cerr << "[" << tag_ << "] Warning: Could not disable IPV6_V6ONLY"
              << std::endl;
  }
  sockaddr_in6 address{};
  address.sin6_family = AF_INET6;
  address.sin6_addr = in6addr_any;
  address.sin6_port = htons(port_);

  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    close(fd);
    return false;
  }

  sockaddr_in6 assignedAddress{};
  socklen_t addressLen = sizeof(assignedAddress);
  if (getsockname(fd, (struct sockaddr *)&assignedAddress, &addressLen) == 0) {
    port_ = ntohs(assignedAddress.sin6_port);
  }

  running_ = true;
  fd_ = fd;
  return true;
}

void SocketResource::stop() {
  if (running_) {
    running_ = false;
    if (server_thread_.joinable())
      server_thread_.join();
  }
}

TCPServer::TCPServer(std::function<void(int)> handler, std::string tag,
                     uint64_t port, std::optional<timeval> recvTimeout)
    : fd_(-1), recvTimeout_(recvTimeout), tag_(tag), handler_(handler) {
  socket_ = std::make_unique<SocketResource>(SOCK_STREAM, port);
}

TCPServer::~TCPServer() { stop(); }

void TCPServer::stop() {
  running_ = false;

  if (fd_ >= 0) {
    shutdown(fd_, SHUT_RDWR);
    close(fd_);
    fd_ = -1;
  }

  if (loopThread_.joinable()) {
    loopThread_.join();
  }

  {
    std::lock_guard<std::mutex> lock(clientMutex_);

    for (int client_fd : clientFDs_) {
      shutdown(client_fd, SHUT_RDWR);
    }
  }

  for (auto &t : clientThreads_) {
    if (t.joinable()) {
      t.join();
    }
  }

  {
    std::lock_guard<std::mutex> lock(clientMutex_);

    for (int client_fd : clientFDs_) {
      close(client_fd);
    }

    clientFDs_.clear();
  }

  clientThreads_.clear();

  if (socket_) {
    socket_->stop();
  }
}

bool TCPServer::start() {
  running_ = true;
  socket_->start(tag_);
  fd_ = socket_->get_fd();

  if (listen(fd_, 5) < 0) {
    std::cerr << "[" << tag_ << "] Listen failed!" << std::endl;
    close(fd_);

    return false;
  }

  std::cout << "[" << tag_ << "] Listening for iOS connections on port "
            << std::dec << int(socket_->get_port()) << "..." << std::endl;

  loopThread_ = std::thread([this]() { server_loop(); });

  return true;
}

void TCPServer::server_loop() {
  while (running_) {
    sockaddr_storage client_addr{};
    socklen_t addrlen = sizeof(client_addr);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd_, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int activity = select(fd_ + 1, &readfds, nullptr, nullptr, &timeout);
    if (activity > 0 && FD_ISSET(fd_, &readfds)) {
      int client_fd = accept(fd_, (struct sockaddr *)&client_addr, &addrlen);
      if (client_fd >= 0) {
        std::cout << "[" << tag_ << "] New client connected!" << std::endl;
        if (recvTimeout_) {
          setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout_.value(),
                     sizeof(recvTimeout_.value()));
        }
        {
          std::lock_guard<std::mutex> lock(clientMutex_);
          clientFDs_.push_back(client_fd);
        }
        clientThreads_.emplace_back(std::thread(handler_, client_fd));
      }
    }
  }
}

UDPServer::UDPServer(std::function<void(const char *data, size_t length,
                                        sockaddr_storage sender)>
                         handler,
                     std::string tag, uint64_t port)
    : fd_(-1), tag_(tag), handler_(handler) {
  socket_ = std::make_unique<SocketResource>(SOCK_DGRAM, port);
}

UDPServer::~UDPServer() { stop(); }

void UDPServer::stop() {
  running_ = false;

  if (fd_ >= 0) {
    shutdown(fd_, SHUT_RDWR);
    close(fd_);
    fd_ = -1;
  }

  if (loopThread_.joinable()) {
    loopThread_.join();
  }

  if (socket_) {
    socket_->stop();
  }
}

bool UDPServer::start() {
  running_ = true;
  socket_->start(tag_);
  fd_ = socket_->get_fd();

  std::cout << "[" << tag_ << "] Listening for iOS connections on port "
            << std::dec << int(socket_->get_port()) << "..." << std::endl;

  loopThread_ = std::thread([this]() { server_loop(); });

  return true;
}

void UDPServer::server_loop() {
  while (running_) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd_, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int activity = select(fd_ + 1, &readfds, nullptr, nullptr, &timeout);
    if (activity > 0 && FD_ISSET(fd_, &readfds)) {

      // 1. Drain the data from the OS buffer immediately
      char buffer[2048];
      sockaddr_storage sender_addr{};
      socklen_t sender_len = sizeof(sender_addr);

      ssize_t bytes = recvfrom(fd_, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&sender_addr, &sender_len);

      if (bytes > 0) {
        handler_(buffer, bytes, sender_addr);
      }
    }
  }
}
