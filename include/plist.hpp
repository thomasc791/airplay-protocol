#pragma once

#include <cstdint>
#include <string>
#include <vector>

class PlistWriter {
public:
  PlistWriter();
  ~PlistWriter();

  struct Value {
    using Array = std::vector<Value>;
    using Dict = std::vector<std::pair<std::string, Value>>;

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

  std::vector<uint8_t> serialize(const PlistWriter::Value &root);

private:
  struct FlatNode {
    Value val;
    std::vector<size_t> objRefs;
  };

  std::vector<FlatNode> objects;
  std::vector<uint64_t> offsets;
  std::vector<uint8_t> out;

  size_t flattenValue(const Value &val);
  void writeObject(const FlatNode &node, uint8_t objectRefSize);
  void writeUIntBytes(uint64_t val, uint8_t numBytes);
  void writeCountedTag(uint8_t baseTag, size_t count);
  uint8_t bytesNeeded(uint64_t maxVal);
  void writeTrailer(uint8_t offsetIntSize, uint8_t objectRefSize,
                    uint64_t numObjects, uint64_t topObject,
                    uint64_t offsetTableOffset);
  void writeBE64(uint8_t *dst, uint64_t val);
};
