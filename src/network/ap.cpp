#include "network/ap.hpp"
#include "utils.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <set>
#include <thread>

namespace fs = std::filesystem;

namespace {
constexpr const char *kConnectionId = "airplay-setup-ap";
constexpr const char *kSsid = "Linux Airplay Receiver";
const fs::path kDnsDir = "/etc/NetworkManager/dnsmasq-shared.d";
const fs::path kDnsFile = kDnsDir / "captive.conf";

template <class Pred> bool pump_until(Pred done, int timeoutMs) {
  const auto end =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  while (!done()) {
    if (std::chrono::steady_clock::now() > end)
      return false;
    g_main_context_iteration(nullptr, FALSE);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return true;
}

struct DeactivateResult {
  bool done = false;
  bool ok = false;
};

} // namespace

bool is_connected(NMDevice *device) {
  if (nm_device_get_state(device) != NM_DEVICE_STATE_ACTIVATED) {
    return false;
  }
  NMActiveConnection *ac = nm_device_get_active_connection(device);
  return ac && g_strcmp0(nm_active_connection_get_id(ac), kConnectionId) != 0;
}

bool enable_captive_dns() {
  std::error_code ec;
  fs::create_directories(kDnsDir, ec);
  if (ec) {
    std::cerr << "Cannot create " << kDnsDir << ": " << ec.message()
              << " (are you root?)" << std::endl;
    return false;
  }

  std::ofstream conf(kDnsFile);
  if (!conf.is_open()) {
    std::cerr << "Cannot write " << kDnsFile << " (are you root?)" << std::endl;
    return false;
  }
  conf << "address=/#/10.42.0.1\n";
  return true;
}

void disable_captive_dns() {
  std::error_code ec;
  fs::remove(kDnsFile, ec);
}

SetupAP::SetupAP(NMClient *client, NMDevice *device)
    : client_(client), device_(device), cancellable_(g_cancellable_new()) {
  if (get_password() <= 0) {
    set_password();
  }
}

int SetupAP::set_password() {
  pw_.resize(12);
  int err = RAND_bytes(pw_.data(), 12);
  pwS_ = chars_to_hex(pw_);

  if (err <= 0) {
    std::cerr << "Error creating RANDOM key" << std::endl;
    return err;
  }

  const char *xdg_data = std::getenv("XDG_DATA_HOME");
  fs::path baseDir =
      xdg_data ? fs::path(xdg_data) : fs::path(std::getenv("HOME"));
  fs::path keyDir = baseDir / "ap";
  fs::path wifiPWPath = keyDir / "identity";

  std::ofstream wifiKeyFile(wifiPWPath);

  if (wifiKeyFile.is_open()) {
    wifiKeyFile << chars_to_hex(pw_);

    wifiKeyFile.close();
  } else {
    std::cerr << "Error writing public key" << std::endl;
    return -1;
  }

  return 1;
}

int SetupAP::get_password() {
  const char *xdg_data = std::getenv("XDG_DATA_HOME");
  fs::path baseDir =
      xdg_data ? fs::path(xdg_data) : fs::path(std::getenv("HOME"));
  fs::path keyDir = baseDir / "ap";
  fs::path wifiPWPath = keyDir / "identity";

  if (!fs::exists(keyDir)) {
    if (!fs::create_directory(keyDir)) {
      std::cerr << "Failed to create directory at " << keyDir << std::endl;

      return -1;
    }
  }
  if (!fs::exists(wifiPWPath)) {
    return -1;
  }

  std::ifstream wifiPWFile(wifiPWPath);
  std::getline(wifiPWFile, pwS_);

  pw_ = hex_to_chars(pwS_);

  std::cout << pwS_ << std::endl;

  return 1;
}

SetupAP::~SetupAP() {
  stop();
  g_cancellable_cancel(cancellable_);
  g_object_unref(cancellable_);
}

void SetupAP::on_activated(GObject *source, GAsyncResult *res, gpointer data) {
  GError *err = nullptr;
  GVariant *out = nullptr;
  NMActiveConnection *active = nm_client_add_and_activate_connection2_finish(
      NM_CLIENT(source), res, &out, &err);
  if (out)
    g_variant_unref(out);

  if (err && g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
    g_error_free(err);
    if (active)
      g_object_unref(active);
    return;
  }

  auto *self = static_cast<SetupAP *>(data);
  if (err) {
    std::cerr << "AP activation failed: " << err->message << std::endl;
    g_error_free(err);
  }
  self->active_ = active; // null on failure
  self->activationDone_ = true;
}

bool SetupAP::start() {
  if (active_)
    return true;

  cleanup_stale();

  if (!enable_captive_dns())
    return false;

  NMConnection *connection = nm_simple_connection_new();

  auto *s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());
  g_object_set(s_con, NM_SETTING_CONNECTION_ID, kConnectionId,
               NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
               NM_SETTING_CONNECTION_AUTOCONNECT, FALSE, nullptr);
  nm_connection_add_setting(connection, NM_SETTING(s_con));

  auto *s_wifi = NM_SETTING_WIRELESS(nm_setting_wireless_new());
  GBytes *ssid = g_bytes_new(kSsid, std::strlen(kSsid));
  g_object_set(s_wifi, NM_SETTING_WIRELESS_SSID, ssid, NM_SETTING_WIRELESS_MODE,
               NM_SETTING_WIRELESS_MODE_AP, NM_SETTING_WIRELESS_BAND, "bg",
               nullptr);
  g_bytes_unref(ssid);
  nm_connection_add_setting(connection, NM_SETTING(s_wifi));

  auto *s_sec =
      NM_SETTING_WIRELESS_SECURITY(nm_setting_wireless_security_new());
  g_object_set(s_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
               NM_SETTING_WIRELESS_SECURITY_PSK, pwS_.c_str(), nullptr);
  nm_setting_wireless_security_add_proto(s_sec, "rsn");
  nm_setting_wireless_security_add_pairwise(s_sec, "ccmp");
  nm_setting_wireless_security_add_group(s_sec, "ccmp");
  nm_connection_add_setting(connection, NM_SETTING(s_sec));

  auto *s_ip4 = NM_SETTING_IP_CONFIG(nm_setting_ip4_config_new());
  g_object_set(s_ip4, NM_SETTING_IP_CONFIG_METHOD,
               NM_SETTING_IP4_CONFIG_METHOD_SHARED, nullptr);
  nm_connection_add_setting(connection, NM_SETTING(s_ip4));

  // "volatile": NetworkManager deletes the profile when it is deactivated, so
  // nothing is left on disk.
  GVariantBuilder opts;
  g_variant_builder_init(&opts, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&opts, "{sv}", "persist",
                        g_variant_new_string("volatile"));

  activationDone_ = false;
  nm_client_add_and_activate_connection2(
      client_, connection, device_, nullptr, g_variant_builder_end(&opts),
      cancellable_, &SetupAP::on_activated, this);
  g_object_unref(connection);

  if (!pump_until([this] { return activationDone_; }, 10000) || !active_) {
    std::cerr << "AP did not activate." << std::endl;
    g_cancellable_cancel(cancellable_); // callback must not touch us later
    cleanup_stale();
    return false;
  }

  const bool up = pump_until(
      [this] {
        const auto s = nm_active_connection_get_state(active_);
        return s == NM_ACTIVE_CONNECTION_STATE_ACTIVATED ||
               s >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
      },
      15000);
  if (!up || nm_active_connection_get_state(active_) !=
                 NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
    std::cerr << "AP did not reach the activated state." << std::endl;
    stop();
    return false;
  }

  std::cout << "Setup AP \"" << kSsid << "\" is up." << std::endl;
  return true;
}

void SetupAP::stop() {
  if (active_) {
    deactivate(active_);
    g_clear_object(&active_);
  }
  disable_captive_dns();
}

bool SetupAP::deactivate(NMActiveConnection *conn) {
  auto result = std::make_shared<DeactivateResult>();
  auto *handle = new std::shared_ptr<DeactivateResult>(result);

  nm_client_deactivate_connection_async(
      client_, conn, nullptr,
      [](GObject *source, GAsyncResult *res, gpointer data) {
        std::unique_ptr<std::shared_ptr<DeactivateResult>> h(
            static_cast<std::shared_ptr<DeactivateResult> *>(data));
        GError *err = nullptr;
        (*h)->ok = nm_client_deactivate_connection_finish(NM_CLIENT(source),
                                                          res, &err);
        if (err) {
          std::cerr << "AP deactivation failed: " << err->message << std::endl;
          g_error_free(err);
        }
        (*h)->done = true;
      },
      handle);

  pump_until([&result] { return result->done; }, 5000);
  return result->ok;
}

// Removes leftovers from a previous run that died without cleaning up: an
// active connection with our id, and the catch-all DNS file.
void SetupAP::cleanup_stale() {
  disable_captive_dns();

  const GPtrArray *conns = nm_client_get_active_connections(client_);
  if (!conns)
    return;

  // Copy first: deactivating changes the array while we iterate.
  std::vector<NMActiveConnection *> stale;
  for (guint i = 0; i < conns->len; i++) {
    auto *c = NM_ACTIVE_CONNECTION(g_ptr_array_index(conns, i));
    const char *id = nm_active_connection_get_id(c);
    if (id && std::strcmp(id, kConnectionId) == 0)
      stale.push_back(static_cast<NMActiveConnection *>(g_object_ref(c)));
  }
  for (auto *c : stale) {
    deactivate(c);
    g_object_unref(c);
  }
}

std::vector<std::string> get_available_ssids(NMClient *client,
                                             const std::string &ifname) {
  std::set<std::string> unique_ssids;
  std::vector<std::string> ssid_list;

  NMDevice *device = nm_client_get_device_by_iface(client, ifname.c_str());
  if (!device || !NM_IS_DEVICE_WIFI(device)) {
    std::cerr << "[libnm] Could not find Wi-Fi device: " << ifname << std::endl;
    return ssid_list;
  }

  const GPtrArray *aps =
      nm_device_wifi_get_access_points(NM_DEVICE_WIFI(device));
  if (!aps)
    return ssid_list;

  for (guint i = 0; i < aps->len; i++) {
    NMAccessPoint *ap = NM_ACCESS_POINT(g_ptr_array_index(aps, i));
    GBytes *ssid_bytes = nm_access_point_get_ssid(ap);
    if (!ssid_bytes)
      continue;

    gsize size;
    const auto *data =
        static_cast<const char *>(g_bytes_get_data(ssid_bytes, &size));
    if (size == 0)
      continue;

    std::string ssid(data, size);
    if (unique_ssids.insert(ssid).second)
      ssid_list.push_back(ssid);
  }
  return ssid_list;
}
