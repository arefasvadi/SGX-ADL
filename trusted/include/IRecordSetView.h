#pragma once

namespace sgx {
  namespace enclave {
    class IRecordSetView {
      public:
      virtual ~IRecordSetView() = default;
      virtual const size_t
      getRecordSetID() const = 0;

      protected:
      private:
      const size_t rSetID_;
    };
  }  // namespace enclave
}  // namespace sgx