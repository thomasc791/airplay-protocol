#include "plist_decoder.hpp"
#include "crypto.hpp"
#include "utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <ranges>
#include <tuple>

PlistDecoder::PlistDecoder() = default;
PlistDecoder::~PlistDecoder() = default;

u8Vec_t PlistDecoder::decode(char *plist, size_t len) {
  u8Vec_t plistBytes(reinterpret_cast<const uint8_t *>(plist),
                     reinterpret_cast<const uint8_t *>(plist) + len);

  std::cout << chars_to_hex(plistBytes) << std::endl;
  read_trailer(plist, len);

  read_offsets(plist);

  uint64_t rootOffset = offsets_[info_.topObject];

  pwVal dictionary = read_dict(plist, rootOffset);

  for (auto e : dictionary.dictVal)
    std::cout << e.key << std::endl << e.value.stringVal << std::endl;

  return {};
}

void PlistDecoder::read_trailer(char *input, size_t len) {
  uint8_t trailerArray[32];
  std::copy(input + len - 32, input + len, std::begin(trailerArray));

  info_.offsetIntSize = trailerArray[6];
  info_.objectRefSize = trailerArray[7];
  read_be64(info_.numObjects, trailerArray + 8);
  read_be64(info_.topObject, trailerArray + 16);
  read_be64(info_.offsetTableOffset, trailerArray + 24);
}

void PlistDecoder::read_offsets(char *plist) {
  offsets_.resize(info_.numObjects);
  uint64_t currentPos = info_.offsetTableOffset;

  for (size_t i = 0; i < info_.numObjects; i++) {
    uint64_t offset = 0;
    for (size_t j = 0; j < info_.offsetIntSize; j++) {
      offset = (offset << 8) | (uint8_t)plist[currentPos++];
    }

    offsets_[i] = offset;
  }
}

int PlistDecoder::get_key_value_indices(char *plist, dict_info_t &dInfo,
                                        const size_t markerOffset) {
  pointer_ = markerOffset;

  auto [type, size] = get_type_size(plist);

  dInfo.keyIndices.resize(size);
  dInfo.keys.resize(size);
  dInfo.valueIndices.resize(size);
  dInfo.values.resize(size);

  for (auto &key : dInfo.keyIndices) {
    key = 0;
    for (size_t i = 0; i < info_.objectRefSize; i++)
      key = (key << 8) | (uint8_t)plist[pointer_++];
  }

  for (auto &value : dInfo.valueIndices) {
    value = 0;
    for (size_t i = 0; i < info_.objectRefSize; i++)
      value = (value << 8) | (uint8_t)plist[pointer_++];
  }

  return 1;
}

uint64_t PlistDecoder::read_write_objects(char *plist,
                                          std::vector<uint64_t> locations,
                                          std::vector<pwVal> &destination,
                                          size_t markerOffset) {
  size_t i = 0;
  for (auto &key : locations) {
    pointer_ = offsets_[key];
    uint64_t currentObjectOffset = pointer_;

    auto [type, size] = get_type_size(plist);

    destination[i] = read_object(plist, type, size, currentObjectOffset);

    i++;
  }
  return 1;
}

std::tuple<uint8_t, uint64_t> PlistDecoder::get_type_size(char *plist) {
  auto keyMarker = (uint8_t)plist[pointer_++];

  uint8_t type = (keyMarker & 0xf0);
  uint64_t size = (keyMarker & 0x0f);
  if (0x0f == size) {
    auto intSize = ((uint8_t)plist[pointer_++] & 0x0f);
    size = 0;
    for (ssize_t i = 0; i < (0x01 << intSize); i++) {
      size = (size << 8) | (uint8_t)plist[pointer_++];
    }
  }

  return {type, size};
}

pwVal PlistDecoder::read_object(char *plist, const uint8_t type,
                                const uint64_t size,
                                const size_t markerOffset) {
  pwVal val;

  switch (type) {
  case 0x00:
    val = size == 0x08 ? pwVal::boolean(false) : pwVal::boolean(true);
    break;
  case 0x10:
    val = read_uint(plist, size);
    break;
  case 0x40:
    val = read_string(plist, size);
    break;
  case 0x50:
    val = read_string(plist, size);
    break;
  case 0xA0:
    val = read_array(plist, size);
    break;
  case 0xD0:
    val = read_dict(plist, markerOffset);
    break;
  }
  return val;
}

pwVal PlistDecoder::read_dict(char *plist, const size_t markerOffset) {
  dict_info_t dInfo;

  get_key_value_indices(plist, dInfo, markerOffset);
  read_write_objects(plist, dInfo.keyIndices, dInfo.keys, markerOffset);

  read_write_objects(plist, dInfo.valueIndices, dInfo.values, markerOffset);

  pwVal::Dict dictionary(dInfo.keys.size());
  for (auto &&[e, k, v] :
       std::ranges::views::zip(dictionary, dInfo.keys, dInfo.values)) {

    e = pwVal::Entry(k.stringVal, v);
  }

  return pwVal::dict(dictionary);
}

pwVal PlistDecoder::read_uint(char *plist, const size_t size) {
  uint64_t value = 0;

  for (size_t i = 0; i < (0x01 << size); i++)
    value = (value << 8) | (uint8_t)plist[pointer_++];

  return pwVal::uint(value);
}

pwVal PlistDecoder::read_string(char *plist, const size_t size) {
  u8Vec_t data(size);

  for (auto &byte : data)
    byte = (uint8_t)plist[pointer_++];

  return pwVal::string(std::string(data.begin(), data.end()));
}

pwVal PlistDecoder::read_array(char *plist, const size_t size) {
  u8Vec_t data(size);

  for (auto &byte : data)
    byte = (uint8_t)plist[pointer_++];

  return pwVal::string(std::string(data.begin(), data.end()));
}

uint64_t PlistDecoder::maximum_value() {
  uint64_t maxVal;
  switch (info_.offsetIntSize) {
  case 0x01:
    maxVal = 0xFF;
    break;
  case 0x02:
    maxVal = 0xFFFF;
    break;
  case 0x08:
    maxVal = 0xFFFFFFFF;
    break;
  }
  return maxVal;
}

void PlistDecoder::read_be64(uint64_t &dst, uint8_t *src) {
  for (int i = 0; i < 8; i++)
    dst |= ((uint64_t)src[i] << ((7 - i) * 8));
}

std::unique_ptr<PlistDecoder> create_plist_decoder() {
  return std::make_unique<PlistDecoder>();
}
