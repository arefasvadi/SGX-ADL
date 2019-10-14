#pragma once

namespace sgx {
  namespace common {
    template <template <template <typename> class, typename> class CRTP,
              template <class>
              class Derived,
              typename T>
    class BaseCRTPThree {
      private:
      friend CRTP<Derived, T>;

      BaseCRTPThree() = default;
      Derived<T> &
      underlying() {
        return static_cast<Derived<T> &>(*this);
      }
      const Derived<T> &
      underlying() const {
        return static_cast<const Derived<T> &>(*this);
      }
    };

    template <template <typename> class CRTP, class Derived>
    class BaseCRTPTwo {
      private:
      friend CRTP<Derived>;

      BaseCRTPTwo() = default;
      Derived &
      underlying() {
        return static_cast<Derived &>(*this);
      }
      const Derived &
      underlying() const {
        return static_cast<const Derived &>(*this);
      }
    };
  }  // namespace common
}  // namespace sgx
