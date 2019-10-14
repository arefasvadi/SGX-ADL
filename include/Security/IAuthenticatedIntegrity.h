#pragma once
#include <vector>

namespace sgx {
  namespace common {
    class IAutheticatedIntegrity {
      public:
      virtual ~IAutheticatedIntegrity() = default;

      virtual std::vector<uint8_t>
      authDigest(const std::vector<uint8_t> &) = 0;

      virtual std::vector<uint8_t>
      authDigestVerify(const std::vector<uint8_t> &) = 0;

      protected:
      private:
    };
  }  // namespace common
}  // namespace sgx