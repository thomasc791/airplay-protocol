#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>

class IMDnsService {
public:
  virtual ~IMDnsService() = default;
  virtual bool start() = 0;
  virtual bool
  publish_service(const std::string &service_name,
                  const std::string &service_type, uint16_t port,
                  const std::map<std::string, std::string> &txt_records) = 0;
  virtual void stop() = 0;
};

std::unique_ptr<IMDnsService> create_mdns_service();
