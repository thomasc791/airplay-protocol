#include "fairplay.hpp"
#include "crypto.hpp"

extern "C" {
#include "playfair.h"

extern const unsigned char default_sap[276];
}

#include <string>
#include <vector>

FairPlayWrapper::FairPlayWrapper() {}

void FairPlayWrapper::set_mode(uint8_t mode) { mode_ = mode; };

void FairPlayWrapper::set_expected_results() {
  std::vector<std::string> expectedDecryptResultsArray = {
      // mode 0 key
      "0496a612172f41e0fd71912acc33fc54",
      // mode 1
      "1512816fbdbe4856570931c3ec7d0e3d",
      // mode 2
      "bc3b888f894276c7dd43c3739a08947c",
      // mode 3
      "63082ff46b87d13d8211e048a696d914",
      // extra
      "2832d44e4dd9f7d3a806562ccd733aba",
      "afb47b92476582fa19d5f2bacbb289b9",
      "eb096a94a2bd2b2480d470c4a562d9bf",
      "b7d8a066bcaed0448601472797a0feb0",
      "97935000cfb79f384d996104362c2045",
      "70e5d54a36a00f4878eba13604a5f3e5",
      "f98a3079b81de696cecca09f18f7ed23",
      "7777a0fc7c9b93d230c4f8795c3f3523",
      "1b21477ed94e634da07769b696fc3e51",
      "671a855130491be5a6c81b2a28a0c466",
      "d6364d68cf353b9f74bb9488c7313b73",
      "6031fc351232683d60b01cd2108e227e",
      "7244f743459404794995317c848e91d9",
      "dae8ac01942b80da0712e2873400acc4",
      "546d85c2b476236e42f2b4906a438c95",
      "7245a3cfeb08e958d4985a19255410ea",
  };

  expectedDecryptResults_ =
      std::vector<u8Vec_t>(expectedDecryptResultsArray.size());

  for (size_t i = 0; i < expectedDecryptResultsArray.size(); i++) {
    AESKeyB64_[i] = u8Vec_t(expectedDecryptResultsArray[i].begin(),
                            expectedDecryptResultsArray[i].end());
  }
}

u8Vec_t FairPlayWrapper::get_fp_cert() {
  auto sap = u8Vec_t(reinterpret_cast<const uint8_t *>(default_sap),
                     reinterpret_cast<const uint8_t *>(default_sap) + 276);
  return sap;
}

std::unique_ptr<FairPlayWrapper> create_fp_wrapper() {
  return std::make_unique<FairPlayWrapper>();
}
