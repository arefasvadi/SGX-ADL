#pragma once
#include <stdint.h>

typedef struct SpecialBufferCommon {
public:
  SpecialBufferCommon() = default;
  virtual ~SpecialBufferCommon() = default;

  static uint64_t overallBytesConsumed_;
  static uint32_t currID_;

} SpecialBufferCommon;