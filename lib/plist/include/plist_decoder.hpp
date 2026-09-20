#pragma once

#include "crypto.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class PlistDecoder {
public:
  PlistDecoder();
  ~PlistDecoder();

  struct Value {
    using Array = std::vector<Value>;
    struct Entry;
    using Dict = std::vector<Entry>;

    enum class Type { Bool, UInt, Data, String, Array, Dict };
    Type type;

    bool boolVal;
    uint64_t uintVal;
    std::string stringVal;
    std::vector<uint8_t> dataVal;
    Array arrayVal;
    Dict dictVal;

    static Value boolean(bool v);
    static Value uint(uint64_t v);
    static Value string(std::string v);
    static Value data(std::vector<uint8_t> v);
    static Value array(Array v);
    static Value dict(Dict v);
  };

  u8Vec_t decode(char *plist, size_t len);
  u8Vec_t serialize(const PlistDecoder::Value &root);

private:
  struct FlatNode {
    Value val;
    std::vector<size_t> objRefs;
  };

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

  trailer_t info_;
  std::vector<FlatNode> objects_;
  std::vector<uint64_t> offsets_;
  std::vector<uint8_t> in_;

  size_t flattenValue(const Value &val);
  void writeObject(const FlatNode &node, uint8_t objectRefSize);
  void writeUIntBytes(uint64_t val, uint8_t numBytes);
  void writeCountedTag(uint8_t baseTag, size_t count);
  uint64_t maximumValue();
  void readTrailer(char *input, size_t len);
  void readOffsets(char *plist);
  uint64_t readObject(char *plist, const uint8_t marker);
  void readBE64(uint64_t &dst, uint8_t *val);
};

struct PlistDecoder::Value::Entry {
  std::string key;
  Value value;
};

std::unique_ptr<PlistDecoder> create_plist_decoder();
