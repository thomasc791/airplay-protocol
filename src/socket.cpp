#include "socket.hpp"
#include "utils.hpp"

#include <cstdint>
#include <ifaddrs.h>
#include <iostream>
#include <memory>
#include <unistd.h>

SocketResource::SocketResource(__socket_type socketType, uint64_t port)
    : fd_(-1), socketType_(socketType), port_(port) {}

SocketResource::~SocketResource() {
  stop();
  log_event(tag_, "Deleting socket.");
}

bool SocketResource::start(std::string tag) {
  tag_ = tag;

  running_ = true;
  fd_ = socket(AF_INET, socketType_, 0);
  if (fd_ < 0) {
    std::cerr << "[" << tag << "] Socket creation failed!" << std::endl;
    return false;
  }

  int opt = 1;
  setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port_);

  if (bind(fd_, (struct sockaddr *)&address, sizeof(address)) < 0) {
    std::cerr << "[" << tag << "] Bind failed!" << std::endl;
    close(fd_);
    running_ = false;
    return false;
  }

  sockaddr_in assignedAddress{};
  socklen_t addressLen = sizeof(assignedAddress);

  if (getsockname(fd_, (struct sockaddr *)&assignedAddress, &addressLen) == 0) {
    port_ = ntohs(assignedAddress.sin_port);
  }

  running_ = true;

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
                     uint64_t port)
    : fd_(-1), tag_(tag), handler_(handler) {
  socket_ = std::make_unique<SocketResource>(SOCK_STREAM, port);
}

bool TCPServer::start() {
  socket_->start(tag_);
  fd_ = socket_->get_fd();

  if (listen(fd_, 5) < 0) {
    std::cerr << "[" << tag_ << "] Listen failed!" << std::endl;
    close(fd_);

    return false;
  }

  std::cout << "[" << tag_ << "] Listening for iOS connections on port "
            << std::dec << int(socket_->get_port()) << "..." << std::endl;

  std::thread([this]() { server_loop(); }).detach();

  return true;
}
void TCPServer::server_loop() {
  while (socket_->is_running()) {
    sockaddr_in client_addr{};
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
        std::thread(handler_, (client_fd)).detach();
      }
    }
  }
  close(fd_);
}

UDPServer::UDPServer(
    std::function<void(const char *data, size_t length, sockaddr_in sender)>
        handler,
    std::string tag, uint64_t port)
    : fd_(-1), tag_(tag), handler_(handler) {
  socket_ = std::make_unique<SocketResource>(SOCK_DGRAM, port);
}

bool UDPServer::start() {
  socket_->start(tag_);
  fd_ = socket_->get_fd();

  std::cout << "[" << tag_ << "] Listening for iOS connections on port "
            << std::dec << int(socket_->get_port()) << "..." << std::endl;

  std::thread([this]() { server_loop(); }).detach();

  return true;
}

void UDPServer::server_loop() {
  while (socket_->is_running()) {
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
      sockaddr_in sender_addr{};
      socklen_t sender_len = sizeof(sender_addr);

      ssize_t bytes = recvfrom(fd_, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&sender_addr, &sender_len);

      if (bytes > 0) {
        handler_(buffer, bytes, sender_addr);
      }
    }
  }
  close(fd_);
}
