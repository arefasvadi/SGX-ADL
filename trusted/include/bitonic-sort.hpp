#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sgx {
namespace trusted {

#define SORT_SPACE_MEGABYTE 20

namespace std = ::std;

// SR : SortRecord
template <typename SR> class BitonicSorter {
public:
  explicit BitonicSorter(const std::size_t arr_len,
                         const SR *array_ptr = nullptr,
                         const bool ascending = true)
      : arrayLen_{arr_len}, arrayPtr_{array_ptr}, ascending_{ascending},
        thresholdNum_{(SORT_SPACE_MEGABYTE * 1048576) / sizeof(SR)} {};

  BitonicSorter(const BitonicSorter &) = delete;
  BitonicSorter &operator=(const BitonicSorter &) = delete;

  BitonicSorter(BitonicSorter &&) = delete;
  BitonicSorter &operator=(BitonicSorter &&) = delete;

  bool doSort();

private:
  void bitonicSort(std::size_t low, std::size_t n, bool dir);
  void bitonicMerge(std::size_t low, std::size_t n, bool dir);
  inline void obliviousCompareExchange(std::size_t i, std::size_t j, bool dir);
  int greatestPowerofTwoLessThan(int n);

  const std::size_t arrayLen_;
  const SR *arrayPtr_;
  const bool ascending_;
  const std::size_t thresholdNum_;
};

template <typename SR> bool BitonicSorter<SR>::doSort() {
  bitonicSort(0, arrayLen_, ascending_);
}

template <typename SR>
void BitonicSorter<SR>::bitonicSort(std::size_t low, std::size_t n, bool dir) {
  if (n > 1) {
    int m = n / 2;
    bitonicSort(low, m, !dir);
    bitonicSort(low + m, n - m, dir);
    bitonicMerge(low, n, dir);
  }
}

template <typename SR>
void BitonicSorter<SR>::bitonicMerge(std::size_t low, std::size_t n, bool dir) {
  if (n > 1) {
    int m = greatestPowerofTwoLessThan(n);

    for (int i = low; i < low + n - m; i++) {
      obliviousCompareExchange(i, i + m, dir);
    }

    bitonicMerge(low, m, dir);
    bitonicMerge(low + m, n - m, dir);
  }
}

template <typename SR>
inline void BitonicSorter<SR>::obliviousCompareExchange(std::size_t i,
                                                        std::size_t j,
                                                        bool dir) {
  uint8_t swap_space[sizeof(SR)];
  SR temp = arrayPtr_[i];

  if (dir == (arrayPtr_[i] > arrayPtr_[j])) {
    // swap should take place
    std::memset(swap_space, 1, sizeof(SR));
  } else {
    // No need for swap
    std::memset(swap_space, 0, sizeof(SR));
  }

  uint8_t *p_i = (uint8_t *)(arrayPtr_ + i);
  uint8_t *p_j = (uint8_t *)(arrayPtr_ + j);
  uint8_t *p_temp = (uint8_t *)(&temp);

  for (int x = 0; x < sizeof(SR); ++x) {
    p_i[x] = swap_space[x] * p_j[x] + (1 - swap_space[x]) * p_temp[x];
    p_j[x] = (1 - swap_space[x]) * p_j[x] + swap_space[x] * p_temp[x];
  }
}

template <typename SR>
int BitonicSorter<SR>::greatestPowerofTwoLessThan(int n) {
  int k = 1;
  while (k > 0 && k < n)
    k = k << 1;
  return k >> 1;
}
}
}
