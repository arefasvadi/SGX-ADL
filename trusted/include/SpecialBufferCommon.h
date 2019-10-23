#pragma once
#include <stdint.h>
#include <vector>
#include "gsl/gsl-lite.hpp"
#include <memory>

typedef struct SpecialBufferCommon {
public:
  SpecialBufferCommon() = default;
  virtual ~SpecialBufferCommon() = default;
  // template<typename T>
  // static gsl::span<T>& getSpan(const size_t size_);
protected:
  static uint64_t overallBytesConsumed_;
  static uint32_t currID_;
private:
  // static std::vector<uint8_t> CommonBuffer_;
  // template<typename T>
  // static std::vector<std::unique_ptr<gsl::span<T>>> inUse_;


} SpecialBufferCommon;

// template<typename T>
// gsl::span<T>& SpecialBufferCommon::getSpan(const size_t size_) {

// }