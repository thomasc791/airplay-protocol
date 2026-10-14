#include "network/ap.hpp"
#include "network/captive.hpp"

#include <NetworkManager.h>
#include <atomic>
#include <csignal>
#include <iostream>
#include <optional>
#include <thread>

#include "airplay_server.hpp"

std::atomic<bool> keep_running{true};

void signal_handler(int) { keep_running = false; }

using namespace std::chrono_literals;

int wifi_setup() {
  const std::string ifname = "wlp0s20f3";

  GError *error = nullptr;
  NMClient *client = nm_client_new(nullptr, &error);
  if (!client) {
    std::cerr << "Failed to connect to NetworkManager: " << error->message
              << std::endl;
    g_clear_error(&error);
    return -1;
  }

  NMDevice *wifiDevice = nm_client_get_device_by_iface(client, ifname.c_str());
  if (!wifiDevice) {
    std::cerr << "Could not find interface " << ifname << std::endl;
    g_object_unref(client);
    return -1;
  }

  if (is_connected(wifiDevice)) {
    return 1;
  }

  auto ssidOptions = get_available_ssids(client, ifname);

  {
    SetupAP ap(client, wifiDevice);
    if (!ap.start()) {
      g_object_unref(client);
      return 1;
    }

    CaptivePortal captive;
    captive.set_ssid_options(ssidOptions);
    captive.start();

    std::optional<Credentials> creds;
    while (keep_running && !(creds = captive.wait_for_credentials(100ms))) {
      g_main_context_iteration(nullptr, FALSE);
      std::this_thread::sleep_for(100ms);
    }

    std::cout << "Shutting down setup AP..." << std::endl;
    captive.stop();
    ap.stop();
  }

  g_object_unref(client);
  return 1;
}

int main() {
  std::signal(SIGHUP, signal_handler);
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  wifi_setup();

  if (!keep_running) {
    return 0;
  }

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
