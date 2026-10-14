#pragma once

#include "crypto.hpp"
#include <NetworkManager.h>
#include <string>
#include <vector>

#define WIFI_DEBUG

class SetupAP {
public:
  SetupAP(NMClient *client, NMDevice *device);
  ~SetupAP();
  SetupAP(const SetupAP &) = delete;
  SetupAP &operator=(const SetupAP &) = delete;

  bool start();
  void stop();
  bool is_active() const { return active_ != nullptr; }

private:
  NMClient *client_; // not owned
  NMDevice *device_; // not owned
  NMActiveConnection *active_ = nullptr;
  GCancellable *cancellable_;
  bool activationDone_ = false;

  u8Vec_t pw_;
  std::string pwS_;

  int set_password();
  int get_password();

  bool deactivate(NMActiveConnection *conn);
  void cleanup_stale();
  static void on_activated(GObject *source, GAsyncResult *res, gpointer self);
};

bool is_connected(NMDevice *device);
bool enable_captive_dns();
void disable_captive_dns();

std::vector<std::string> get_available_ssids(NMClient *client,
                                             const std::string &ifname);
