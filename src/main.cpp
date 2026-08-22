#include "airplay_server.hpp"
#include <atomic>
#include <csignal>
#include <iostream>

std::atomic<bool> keep_running{true};

void signal_handler(int) { keep_running = false; }

int main() {
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  std::cout
      << "Starting Portable C++ AirPlay Receiver (Linux / Raspberry Pi)..."
      << std::endl;

  AirPlayServer server("Linux AirPlay Receiver", 7000);
  if (!server.start()) {
    std::cerr << "Failed to start AirPlay server." << std::endl;
    return 1;
  }

  std::cout << "Server running. Press Ctrl+C to terminate." << std::endl;

  while (keep_running) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  std::cout << "Shutting down AirPlay server..." << std::endl;
  server.stop();

  return 0;
}
