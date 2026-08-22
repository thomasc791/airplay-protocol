# Portable C++ AirPlay Receiver (Linux / Raspberry Pi)

This repository is a ported version of `esp-airplay` abstracted from ESP32/ESP-IDF hardware dependencies to run on Linux machines (PC, Raspberry Pi, etc.).

## Project Structure
- `CMakeLists.txt`: Standard Linux CMake configuration.
- `include/hal/`: Hardware Abstraction Layer headers (sockets, standard C++ thread queues, mDNS interface).
- `src/hal/`: Avahi client implementation for mDNS advertising on Linux.
- `src/airplay_server.cpp`: Main socket listener and request handler.
- `src/main.cpp`: Entry point handling process signals and server lifecycle.

## Dependencies

Before compiling on Debian/Ubuntu/Raspberry Pi OS, install the necessary development packages:

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libssl-dev libavahi-client-dev
