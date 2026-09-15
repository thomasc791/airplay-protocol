#pragma once

#include "crypto.hpp"
#include <cstdint>
#include <memory>
#include <vector>

class FairPlayWrapper {
public:
  FairPlayWrapper();
  ~FairPlayWrapper() = default;

  void set_mode(uint8_t mode);
  void set_key_msg(char *msg);

  u8Vec_t get_reply_message();
  u8Vec_t get_reply_header() { return replyHeader_; }

private:
  std::vector<std::vector<uint8_t>> AESKeyB64_, keyMsgHex_,
      expectedDecryptResults_;

  std::vector<u8Vec_t> replyMessage_;

  u8Vec_t keyMessage_;
  u8Vec_t replyHeader_;

  uint8_t mode_;

  void set_aesb64();
  void set_reply_message();
};

std::unique_ptr<FairPlayWrapper> create_fp_wrapper();
