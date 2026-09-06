#pragma once

#include "crypto.hpp"
#include <cstdint>
#include <memory>
#include <vector>

class FairPlayWrapper {
public:
  FairPlayWrapper();
  ~FairPlayWrapper() = default;

  u8Vec_t get_fp_cert();

private:
  std::vector<std::vector<uint8_t>> AESKeyB64_, keyMsgHex_,
      expectedDecryptResults_;

  void set_aesb64();
  void set_key_msg_hex();
  void set_expected_results();
};

std::unique_ptr<FairPlayWrapper> create_fp_wrapper();
