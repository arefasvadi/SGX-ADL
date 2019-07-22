#pragma once
#include <stdint.h>

typedef struct SpecialBufferCommon {
  static uint64_t overallBytesConsumed_;
  static uint32_t currID_;
} SpecialBufferCommon;