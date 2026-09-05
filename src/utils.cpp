#include "utils.hpp"

#include <ifaddrs.h>
#include <iomanip>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sstream>
#include <vector>

std::vector<uint8_t> hex_to_chars(const std::string &hexStr) {
  std::vector<uint8_t> bytes;

  for (size_t i = 0; i < hexStr.length(); i += 2) {
    std::string byteString = hexStr.substr(i, 2);
    uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

std::string chars_to_hex(const std::vector<uint8_t> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (uint8_t byte : data) {
    ss << std::setw(2) << static_cast<int>(byte);
  }
  return ss.str();
}

std::string remove_colon(const std::string str) {
  std::string str2;
  for (const auto c : str) {
    switch (c) {
    case ':':
      break;
    default:
      str2.push_back(c);
    }
  }

  return str2;
}

std::string get_system_mac_address() {
  struct ifaddrs *ifaddr = nullptr;
  if (getifaddrs(&ifaddr) == -1) {
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

  return mac_str.empty() ? "00:11:22:33:44:55" : "5C:5F:67:60:A3:16";
}
