#pragma once
#include <stdint.h>
#include <vector>
#include <memory>

typedef struct SpecialBufferCommon {
public:
  SpecialBufferCommon() = default;
  virtual ~SpecialBufferCommon() = default;
protected:
  static uint64_t overallBytesConsumed_;
  static uint32_t currID_;
private:
} SpecialBufferCommon;