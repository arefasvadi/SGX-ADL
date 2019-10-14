#pragma once

namespace sgx {
  namespace common {
    class IIntegrity {
      public:
      virtual ~IIntegrity() = default;

      virtual std::vector<uint8_t>
      digest(const std::vector<uint8_t> &) = 0;

      virtual std::vector<uint8_t>
      verifyDigest(const std::vector<uint8_t> &) = 0;

      protected:
      private:
    };
  }  // namespace common
}  // namespace sgx