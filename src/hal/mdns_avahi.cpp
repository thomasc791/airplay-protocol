#include "hal/mdns_service.hpp"
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <iostream>
#include <sys/socket.h>

class AvahiMDnsService : public IMDnsService {
private:
  AvahiSimplePoll *poll_ = nullptr;
  AvahiClient *client_ = nullptr;
  AvahiEntryGroup *group_ = nullptr;

  static void client_callback(AvahiClient *c, AvahiClientState state,
                              AVAHI_GCC_UNUSED void *userdata) {
    if (state == AVAHI_CLIENT_FAILURE) {
      std::cerr << "[mDNS] Client failure: "
                << avahi_strerror(avahi_client_errno(c)) << std::endl;
    }
  }

public:
  ~AvahiMDnsService() override { stop(); }

  bool start() override {
    int error;
    poll_ = avahi_simple_poll_new();
    if (!poll_)
      return false;

    client_ =
        avahi_client_new(avahi_simple_poll_get(poll_), AVAHI_CLIENT_NO_FAIL,
                         client_callback, nullptr, &error);
    if (!client_) {
      std::cerr << "[mDNS] Failed to create Avahi client: "
                << avahi_strerror(error) << std::endl;
      return false;
    }
    return true;
  }

  bool publish_service(const std::string &name, const std::string &type,
                       uint16_t port,
                       const std::map<std::string, std::string> &txt) override {
    if (!client_)
      return false;

    group_ = avahi_entry_group_new(client_, nullptr, nullptr);
    if (!group_)
      return false;

    AvahiStringList *txt_list = nullptr;
    for (const auto &[k, v] : txt) {
      std::string record = k + "=" + v;
      txt_list = avahi_string_list_add(txt_list, record.c_str());
    }

    int ret = avahi_entry_group_add_service_strlst(
        group_, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, (AvahiPublishFlags)0,
        name.c_str(), type.c_str(), nullptr, nullptr, port, txt_list);

    avahi_string_list_free(txt_list);
    if (ret < 0) {
      std::cerr << "[mDNS] Failed to add service: " << avahi_strerror(ret)
                << std::endl;
      return false;
    }

    return avahi_entry_group_commit(group_) == 0;
  }

  void stop() override {
    if (group_) {
      avahi_entry_group_free(group_);
      group_ = nullptr;
    }
    if (client_) {
      avahi_client_free(client_);
      client_ = nullptr;
    }
    if (poll_) {
      avahi_simple_poll_free(poll_);
      poll_ = nullptr;
    }
  }
};

std::unique_ptr<IMDnsService> create_mdns_service() {
  return std::make_unique<AvahiMDnsService>();
}
