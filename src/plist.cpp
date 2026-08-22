#include "plist.hpp"

using plw = PlistWriter;
using pwVal = PlistWriter::Value;

plw::PlistWriter() = default;
plw::~PlistWriter() = default;

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

std::vector<uint8_t> plw::serialize(const pwVal &root) {
  objects.clear();
  offsets.clear();
  out.clear();

  // 1. Flatten all objects into the object table
  flattenValue(root);

  uint8_t objectRefSize = bytesNeeded(objects.size());

  // 2. Write magic
  const char *magic = "bplist00";
  out.insert(out.end(), magic, magic + 8);

  // 3. Write each object, recording its offset
  for (const auto &obj : objects) {
    offsets.push_back(out.size());
    writeObject(obj, objectRefSize);
  }

  // 4. Write offset table
  uint64_t offsetTableOffset = out.size();
  uint8_t offsetIntSize = bytesNeeded(out.size());
  for (uint64_t off : offsets) {
    writeUIntBytes(off, offsetIntSize);
  }

  // 5. Write 32-byte trailer
  writeTrailer(offsetIntSize, objectRefSize, objects.size(), 0,
               offsetTableOffset);

  return out;
}

size_t plw::flattenValue(const pwVal &val) {
  size_t myIdx = objects.size();
  objects.push_back({val, {}}); // Insert placeholder

  std::vector<size_t> refs;

  if (val.type == pwVal::Type::Dict) {
    // bplist requires ALL keys first, then ALL values
    for (const auto &pair : val.dictVal) {
      refs.push_back(flattenValue(pwVal::string(pair.first)));
    }
    for (const auto &pair : val.dictVal) {
      refs.push_back(flattenValue(pair.second));
    }
  } else if (val.type == pwVal::Type::Array) {
    for (const auto &e : val.arrayVal) {
      refs.push_back(flattenValue(e));
    }
  }

  // Attach correct child references to parent
  objects[myIdx].objRefs = refs;
  return myIdx;
}

void plw::writeObject(const FlatNode &node, uint8_t objectRefSize) {
  const Value &val = node.val;
  switch (val.type) {
  case Value::Type::Bool: {
    out.push_back(val.boolVal ? 0x09 : 0x08);
    break;
  }
  case Value::Type::UInt: {
    uint8_t log2width;
    if (val.uintVal <= 0xFF)
      log2width = 0;
    else if (val.uintVal <= 0xFFFF)
      log2width = 1;
    else if (val.uintVal <= 0xFFFFFFFF)
      log2width = 2;
    else
      log2width = 3;

    out.push_back(0x10 | log2width);
    writeUIntBytes(val.uintVal, 1 << log2width);
    break;
  }
  case Value::Type::String: {
    writeCountedTag(0x50, val.stringVal.size());
    out.insert(out.end(), val.stringVal.begin(), val.stringVal.end());
    break;
  }
  case Value::Type::Data: {
    writeCountedTag(0x40, val.dataVal.size());
    out.insert(out.end(), val.dataVal.begin(), val.dataVal.end());
    break;
  }
  case Value::Type::Array: {
    writeCountedTag(0xA0, node.objRefs.size());
    for (size_t ref : node.objRefs) {
      writeUIntBytes(ref, objectRefSize);
    }
    break;
  }
  case Value::Type::Dict: {
    // Dict tag count is the number of key-value PAIRS, not total refs
    writeCountedTag(0xD0, node.objRefs.size() / 2);
    for (size_t ref : node.objRefs) {
      writeUIntBytes(ref, objectRefSize);
    }
    break;
  }
  }
}

void plw::writeUIntBytes(uint64_t val, uint8_t numBytes) {
  for (int i = numBytes - 1; i >= 0; i--)
    out.push_back((val >> (i * 8)) & 0xFF);
}

void plw::writeCountedTag(uint8_t baseTag, size_t count) {
  if (count < 0xF) {
    out.push_back(baseTag | static_cast<uint8_t>(count));
  } else {
    out.push_back(baseTag | 0xF);
    // Write size as an integer object
    Value countVal = Value::uint(count);
    FlatNode tempNode = {countVal, {}};
    writeObject(tempNode, 0);
  }
}

uint8_t plw::bytesNeeded(uint64_t maxVal) {
  if (maxVal <= 0xFF)
    return 1;
  if (maxVal <= 0xFFFF)
    return 2;
  if (maxVal <= 0xFFFFFFFF)
    return 4;
  return 8;
}

void plw::writeTrailer(uint8_t offsetIntSize, uint8_t objectRefSize,
                       uint64_t numObjects, uint64_t topObject,
                       uint64_t offsetTableOffset) {
  uint8_t trailer[32] = {}; // Valid BPLIST trailer is exactly 32 bytes
  trailer[6] = offsetIntSize;
  trailer[7] = objectRefSize;
  writeBE64(trailer + 8, numObjects);
  writeBE64(trailer + 16, topObject);
  writeBE64(trailer + 24, offsetTableOffset);
  out.insert(out.end(), trailer, trailer + 32);
}

void plw::writeBE64(uint8_t *dst, uint64_t val) {
  for (int i = 7; i >= 0; i--)
    dst[i] = val & 0xFF, val >>= 8;
}
