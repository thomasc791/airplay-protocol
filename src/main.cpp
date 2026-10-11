#include "network/ap.hpp"
#include "network/captive.hpp"
#include <atomic>
#include <csignal>
#include <iostream>
#include <thread>

std::atomic<bool> keep_running{true};

void signal_handler(int) { keep_running = false; }

#ifndef WIFI_DEBUG

#include "airplay_server.hpp"

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
#endif

#ifdef WIFI_DEBUG

int main() {
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  const std::string ifname = "wlp0s20f3";

  GError *error = nullptr;
  NMClient *client = nm_client_new(nullptr, &error);
  if (!client) {
    std::cerr << "Failed to connect to NetworkManager: " << error->message
              << std::endl;
    g_clear_error(&error);
    return 1;
  }

  NMDevice *wifiDevice = nm_client_get_device_by_iface(client, ifname.c_str());
  if (!wifiDevice) {
    std::cerr << "Could not find interface " << ifname << std::endl;
    g_object_unref(client);
    return 1;
  }

  // Read the scan list BEFORE the hotspot comes up: many adapters cannot scan
  // while running as an access point.
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

    // The GLib context must keep running so libnm can deliver its callbacks.
    while (keep_running) {
      g_main_context_iteration(nullptr, FALSE);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "Shutting down setup AP..." << std::endl;
    captive.stop(); // stop serving first
    ap.stop();      // then remove the hotspot and the DNS file
  } // ~CaptivePortal, then ~SetupAP (both idempotent)

  g_object_unref(client);
  return 0;
}

#endif
