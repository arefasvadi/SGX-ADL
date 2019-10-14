#pragma once
#include <vector>

namespace sgx {
  namespace common {
    class IEncryption {
      public:
      virtual ~IEncryption() = default;

      virtual std::vector<uint8_t>
      encrypt(const std::vector<uint8_t> &) = 0;

      virtual std::vector<uint8_t>
      decrypt(const std::vector<uint8_t> &) = 0;

      protected:
      private:
    };
  }  // namespace common
}  // namespace sgx