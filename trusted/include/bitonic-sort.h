#pragma once

#include "CryptoEngine.hpp"
#include "common.h"
#include "enclave-app.h"
#include "enclave_t.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <tuple>
#include <unordered_map>
#include <vector>
// #define SORT_SPACE_MEGABYTE 20

namespace sgx {
namespace trusted {

namespace std = ::std;

// SR : SortRecord
// template <typename SR>
class BitonicSorter {
public:
  explicit BitonicSorter(const std::size_t arr_len,
                         // const SR *array_ptr = nullptr,
                         const bool ascending,
                         CryptoEngine<uint8_t> &crypto_engine)
      : arrayLen_{arr_len},
        // arrayPtr_{nullptr},
        ascending_{ascending},
        // thresholdNum_{(SORT_SPACE_MEGABYTE * 1048576) / sizeof(SR)}
        cryptoEngine_{crypto_engine} {
          LRUCache_.reserve(CACHE_MAX_SIZE); 
        };

  BitonicSorter(const BitonicSorter &) = delete;
  BitonicSorter &operator=(const BitonicSorter &) = delete;

  BitonicSorter(BitonicSorter &&) = delete;
  BitonicSorter &operator=(BitonicSorter &&) = delete;

  bool doSort();

  static constexpr size_t CACHE_MAX_SIZE = 4096;
  static constexpr size_t CACHE_NEIGHBOR_BRING = 1024;
  // static constexpr size_t OCALL_SIMALTANEOUS_LOAD = 8;

private:
  void bitonicSort(std::size_t low, std::size_t n, bool dir);
  void bitonicMerge(std::size_t low, std::size_t n, bool dir);
  //inline
  void obliviousCompareExchange(std::size_t i, std::size_t j, bool dir);
  int greatestPowerofTwoLessThan(int n);
  //inline
  void prepareRecords(int i, int j);
  //inline
  void addToCache(const std::vector<size_t> &not_in_cache_neighbours);
  //inline
  void removeFromCache(const std::vector<size_t> &in_cache_delete);
  //inline
  void handleCache(int i, std::vector<size_t> &not_in_cache_neighbours,
                          std::vector<size_t> &in_cache_delete);
  const std::size_t arrayLen_;
  // const SR *arrayPtr_;
  const bool ascending_;
  // const std::size_t thresholdNum_;
  CryptoEngine<uint8_t> &cryptoEngine_;

  // map<index,record>
  std::unordered_map<size_t, trainRecordSerialized> LRUCache_;

  // map<time,index>
  // I don use iterators since it will require 8 bytes in 64 bit machines and
  // all indices that I have will require 4 bytes
  std::map<uint32_t, size_t> LRUCounts_;

  // map<index, count>
  // std::unordered_map<size_t,uint32_t> LRURevCounts_;
  // I doubt if we need more than this amount of access during sort
  uint32_t Time_ = 0;
  // uint32_t lastInd_ = 0;
};
}
}
