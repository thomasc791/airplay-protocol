#include "plist_decoder.hpp"
#include "crypto.hpp"
#include "utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>

using pwVal = PlistDecoder::Value;

PlistDecoder::PlistDecoder() = default;
PlistDecoder::~PlistDecoder() = default;

pwVal pwVal::boolean(bool v) {
  Value val;
  val.type = Type::Bool;
  val.boolVal = v;
  return val;
}
pwVal pwVal::uint(uint64_t v) {
  Value val;
  val.type = Type::UInt;
  val.uintVal = v;
  return val;
}
pwVal pwVal::string(std::string v) {
  Value val;
  val.type = Type::String;
  val.stringVal = std::move(v);
  return val;
}
pwVal pwVal::data(std::vector<uint8_t> v) {
  Value val;
  val.type = Type::Data;
  val.dataVal = std::move(v);
  return val;
}
pwVal pwVal::array(Array v) {
  Value val;
  val.type = Type::Array;
  val.arrayVal = std::move(v);
  return val;
}
pwVal pwVal::dict(Dict v) {
  Value val;
  val.type = Type::Dict;
  val.dictVal = std::move(v);
  return val;
}

u8Vec_t PlistDecoder::decode(char *plist, size_t len) {
  u8Vec_t plistBytes(reinterpret_cast<const uint8_t *>(plist),
                     reinterpret_cast<const uint8_t *>(plist) + len);

  std::cout << chars_to_hex(plistBytes) << std::endl;
  readTrailer(plist, len);

  std::cout << "Number of Objects: " << int(info_.numObjects) << std::endl;
  std::cout << "Top Object: " << int(info_.topObject) << std::endl;
  std::cout << "Table size: " << int(info_.offsetTableOffset) << std::endl;
  std::cout << "Int Size Offset: " << int(info_.offsetIntSize) << std::endl;
  std::cout << "Object reference size: " << int(info_.objectRefSize)
            << std::endl;

  uint64_t maxVal = maximumValue();
  readOffsets(plist);

  uint64_t rootOffset = offsets_[info_.topObject];
  uint8_t rootMarker = plist[rootOffset];

  std::cout << "Root: " << rootOffset << std::endl;
  readObject(plist, rootMarker);

  return {};
}

void PlistDecoder::readTrailer(char *input, size_t len) {
  uint8_t trailerArray[32];
  std::copy(input + len - 32, input + len, std::begin(trailerArray));

  info_.offsetIntSize = trailerArray[6];
  info_.objectRefSize = trailerArray[7];
  readBE64(info_.numObjects, trailerArray + 8);
  readBE64(info_.topObject, trailerArray + 16);
  readBE64(info_.offsetTableOffset, trailerArray + 24);
}

void PlistDecoder::readOffsets(char *plist) {
  offsets_.resize(info_.numObjects);
  uint64_t currentPos = info_.offsetTableOffset;

  for (size_t i = 0; i < info_.numObjects; i++) {
    uint64_t offset = 0;
    for (size_t j = 0; j < info_.offsetIntSize; j++) {
      offset = (offset << 8) | plist[currentPos++];
    }

    offsets_[i] = offset;
  }
}

uint64_t PlistDecoder::readObject(char *plist, const uint8_t marker) {
  uint8_t markerByte = plist[marker];

  printf("Marker: %02x", markerByte);
  return 0;
}

uint64_t PlistDecoder::maximumValue() {
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

void PlistDecoder::readBE64(uint64_t &dst, uint8_t *src) {
  for (int i = 0; i < 8; i++)
    dst |= (src[i] << ((7 - i) * 8));
}

std::unique_ptr<PlistDecoder> create_plist_decoder() {
  return std::make_unique<PlistDecoder>();
}
