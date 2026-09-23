#include "tcp.hpp"

#include <future>
#include <ifaddrs.h>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <unistd.h>

TcpListener::~TcpListener() { stop(); }

bool TcpListener::start(uint64_t requested_port, std::string tag) {
  auto port_promise = std::make_shared<std::promise<uint64_t>>();
  auto future = port_promise->get_future();

  running_ = true;
  server_thread_ =
      std::thread(&create_and_bind_socket, handler_, tag, requested_port,
                  std::ref(running_), port_promise);

  port_ = future.get();
  return true;
}

void TcpListener::stop() {
  if (running_) {
    running_ = false;
    if (server_thread_.joinable())
      server_thread_.join();
  }
}

void create_and_bind_socket(
    std::function<void(int)> handler, std::string tag, uint64_t port,
    std::atomic<bool> &running,
    std::shared_ptr<std::promise<uint64_t>> promisePort) {

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "[" << tag << "] Socket creation failed!" << std::endl;
    return;
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    std::cerr << "[" << tag << "] Bind failed!" << std::endl;
    close(server_fd);
    return;
  }

  if (listen(server_fd, 5) < 0) {
    std::cerr << "[" << tag << "] Listen failed!" << std::endl;
    close(server_fd);
    return;
  }

  uint64_t actualPort = port;

  if (promisePort) {
    sockaddr_in assignedAddress{};
    socklen_t addressLen = sizeof(assignedAddress);

    if (getsockname(server_fd, (struct sockaddr *)&assignedAddress,
                    &addressLen) == 0) {
      actualPort = ntohs(assignedAddress.sin_port);
      promisePort->set_value(actualPort);
    }
  }

  std::cout << "[" << tag << "] Listening for iOS connections on port "
            << std::dec << int(actualPort) << "..." << std::endl;

  while (running) {
    sockaddr_in client_addr{};
    socklen_t addrlen = sizeof(client_addr);

    // Simple select to make socket non-blocking for clean shutdown
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int activity = select(server_fd + 1, &readfds, nullptr, nullptr, &timeout);
    if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
      int client_fd =
          accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
      if (client_fd >= 0) {
        std::cout << "[" << tag << "] New client connected!" << std::endl;
        std::thread(handler, (client_fd)).detach();
      }
    }
  }

  close(server_fd);
}
