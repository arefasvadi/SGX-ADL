#pragma once

#include <vector>

template<typename ObjectT>
struct FlatBufferedContainerT_ {
  std::vector<uint8_t> vecBuff;
  ObjectT* objPtr = nullptr;
};

template<typename ObjectT>
using FlatBufferedContainerT = FlatBufferedContainerT_<ObjectT>;

