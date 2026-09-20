#pragma once

#include "crypto.hpp"
#include "plist_encoder.hpp"
#include <cstdint>
#include <memory>
#include <vector>

using pwVal = PlistEncoder::Value;

class PlistDecoder {
public:
  PlistDecoder();
  ~PlistDecoder();

  u8Vec_t decode(char *plist, size_t len);
  u8Vec_t serialize(const pwVal &root);

private:
  struct trailer_t {
    uint64_t numObjects;
    uint64_t topObject;
    uint64_t offsetTableOffset;
    uint8_t offsetIntSize;
    uint8_t objectRefSize;

    trailer_t()
        : numObjects(0), topObject(0), offsetTableOffset(0), offsetIntSize(0),
          objectRefSize(0) {}
  };

  struct dict_info_t {
    std::vector<uint64_t> keyIndices;
    std::vector<uint64_t> valueIndices;
    std::vector<pwVal> keys;
    std::vector<pwVal> values;
  };

  trailer_t info_;
  std::vector<uint64_t> offsets_;
  std::vector<uint8_t> in_;

  size_t pointer_;

  size_t flatten_value(const pwVal &val);
  void write_uint_bytes(uint64_t val, uint8_t numBytes);
  void write_counted_tag(uint8_t baseTag, size_t count);
  uint64_t maximum_value();
  void read_trailer(char *input, size_t len);
  void read_offsets(char *plist);

  pwVal read_dict(char *plist, const uint8_t markerOffset);

  std::tuple<uint8_t, uint64_t> get_type_size(char *plist);

  // for dicts
  int get_key_value_indices(char *plist, dict_info_t &dInfo,
                            const uint8_t markerOffset);

  uint64_t read_write_objects(char *plist, std::vector<uint64_t> locations,
                              std::vector<pwVal> &destination,
                              size_t markerOffset);
  uint64_t read_values(char *plist);
  pwVal read_object(char *plist, const uint8_t type, const uint64_t size,
                    const size_t markerOffset);

  pwVal read_uint(char *plist, const size_t size);
  pwVal read_string(char *plist, const size_t size);
  pwVal read_array(char *plist, const size_t size);
  pwVal read_data(char *plist, const size_t size);

  void read_be64(uint64_t &dst, uint8_t *val);
};

std::unique_ptr<PlistDecoder> create_plist_decoder();
