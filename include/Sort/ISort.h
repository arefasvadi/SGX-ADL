#pragma onnce
#include <functional>
namespace sgx {
  namespace common {
    class ISortable {
      public:
      enum class Direction { ASCENDING = 0, DESCENDING = 1 };

      explicit ISortable(const size_t total) : totalElements_(total){};
      virtual ~ISortable() = default;

      virtual void
      sort(const Direction direction) const = 0;

      protected:
      private:
      const size_t totalElements_;
    }
  }  // namespace common
}  // namespace sgx