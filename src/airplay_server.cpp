#include "airplay_server.hpp"
#include "crypto.hpp"
#include "flags.hpp"
#include "utils.hpp"

#include <avahi-client/client.h>
#include <cstring>
#include <ifaddrs.h>
#include <iomanip>
#include <iostream>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sstream>
#include <unistd.h>

AirPlayServer::AirPlayServer(const std::string &device_name, uint16_t port)
    : port_(port), deviceName_(device_name) {

  device_id_ = get_system_mac_address();
}

AirPlayServer::~AirPlayServer() { stop(); }

bool AirPlayServer::start() {
  mdns_ = create_mdns_service();
  cryptoHandler_ = create_crypto_handler();
  featureFlags_ = create_feature_flags();
  statusFlags_ = create_status_flags();

  if (mdns_->start()) {
    if (publish_airplay_service() < 0)
      std::cerr << "Failed to publish airplay service." << std::endl;
    std::cout << "[AirPlayServer] Published AirPlay mDNS service: "
              << deviceName_ << " on port " << 7000 << std::endl;

    if (publish_raop_service() < 0)
      std::cerr << "Failed to publish raop service." << std::endl;
    std::cout << "[AirPlayServer] Published RAOP mDNS service: " << deviceName_
              << " on port " << 5000 << std::endl;
  }

  running_ = true;
  server_thread_ = std::thread(&AirPlayServer::run, this);
  return true;
}

int AirPlayServer::publish_airplay_service() {
  std::map<std::string, std::string> txt = {
      {"acl", "0"},
      {"deviceid", device_id_},
      {"features", featureFlags_->getHex()},
      {"flags", statusFlags_->getHex()},
      {"gid", "767e31b2-9074-4be0-a3ad-4c0b491877ca"},
      {"gcgl", "0"},
      {"model", "AudioAccessory6,1"},
      // {"pk", crypto_handler_->get_public_hex_string()},
      // {"igl", "0"},
      {"protovers", "1.1"},
      {"rsf", "0x0"},
      {"serialNumber", device_id_},
      {"srcvers", "366.0"},
  };
  mdns_->publish_service(deviceName_, "_airplay._tcp", 7000, txt);
  return 0;
}

int AirPlayServer::publish_raop_service() {
  std::map<std::string, std::string> txt = {
      // {"pk", crypto_handler_->get_public_hex_string()},
      {"ch", "2"},
      {"cn", "0,1,2"},
      // {"et", "0,4"},
      // {"am", "Linux"},
      // {"tp", "UDP"},
      // {"md", "2"},
      // {"vn", "65537"},
      // {"srcvers", "366.0"},
      {"pi", "767e31b2-9074-4be0-a3ad-4c0b491877ca"},
      {"pw", "true"},
      // {"da", "true"},
      {"ft", featureFlags_->getHex()},
      {"sf", statusFlags_->getHex()},
      // {"deviceid", device_id_},
  };
  mdns_->publish_service(deviceName_, "_raop._tcp", 5000, txt);
  return 0;
}

void AirPlayServer::stop() {
  if (running_) {
    running_ = false;
    if (server_thread_.joinable())
      server_thread_.join();
  }
  if (mdns_)
    mdns_->stop();
}

void AirPlayServer::run() {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "[AirPlayServer] Socket creation failed!" << std::endl;
    return;
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port_);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    std::cerr << "[AirPlayServer] Bind failed!" << std::endl;
    close(server_fd);
    return;
  }

  if (listen(server_fd, 5) < 0) {
    std::cerr << "[AirPlayServer] Listen failed!" << std::endl;
    close(server_fd);
    return;
  }

  std::cout << "[AirPlayServer] Listening for iOS connections on port " << port_
            << "..." << std::endl;

  while (running_) {
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
        std::cout << "[AirPlayServer] New client connected!" << std::endl;
        std::thread(&AirPlayServer::handle_client, this, client_fd).detach();
      }
    }
  }

  close(server_fd);
}

void AirPlayServer::handle_client(int client_fd) {
  std::cout << "Created new RTSP handler for client with ID: " << client_fd
            << std::endl
            << "Starting new RTSP parser..." << std::endl;
  rtspParser_ = create_rtsp_parser(client_fd, cryptoHandler_, featureFlags_,
                                   statusFlags_);
  char buffer[2048] = {0};
  while (running_) {
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
      std::cout << "Client " << client_fd << " disconnected." << std::endl;
      break;
    }

    rtspParser_->set_msg(buffer, bytes_read);
    rtspParser_->parse_message();
  }
  close(client_fd);
}

std::string get_system_mac_address() {
  struct ifaddrs *ifaddr = nullptr;
  if (getifaddrs(&ifaddr) != -1) {
    return "00:11:22:33:44:08"; // Fallback MAC if call fails
  }

  std::string mac_str = "";

  for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr)
      continue;

    // Skip loopback interfaces (lo) and inactive interfaces
    if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) {
      continue;
    }

    // AF_PACKET is the socket family for Linux physical layer addresses
    if (ifa->ifa_addr->sa_family == AF_PACKET) {
      auto *s = reinterpret_cast<struct sockaddr_ll *>(ifa->ifa_addr);
      if (s->sll_halen == 6) { // 6-byte Ethernet MAC address
        std::ostringstream ss;
        for (int i = 0; i < 6; ++i) {
          if (i > 0)
            ss << ":";
          ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex
             << static_cast<int>(s->sll_addr[i]);
        }
        mac_str = ss.str();
        break; // Use the first active non-loopback interface (eth0, wlan0,
               // etc.)
      }
    }
  }

  freeifaddrs(ifaddr);

  return mac_str.empty() ? "00:11:22:33:44:55" : mac_str;
}
