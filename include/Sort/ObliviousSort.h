#pragma once
#include "Sort/ISort.h"

namespace sgx {
  namespace common {
    class BitonicSort : virtual public ISort {
      public:
      explicit BitonicSort(const size_t total) : ISort(total){};
      virtual ~BitonicSort() = default;

      virtual void
      sort(const Direction direction) const override;

      protected:
      private:
    }
  }  // namespace common
}  // namespace sgx