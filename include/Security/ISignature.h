#pragma once

namespace sgx {
  namespace common {
    class ISignature {
      public:
      virtual ~ISignature() = default;

      virtual std::vector<uint8_t>
      sign(const std::vector<uint8_t> &) = 0;

      virtual std::vector<uint8_t>
      verifySignature(const std::vector<uint8_t> &) = 0;

      protected:
      private:
    };
  }  // namespace common
}  // namespace sgx