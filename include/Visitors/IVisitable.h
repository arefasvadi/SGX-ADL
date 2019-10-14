#pragma once

namespace sgx {
  namespace common {
    class IVisitor;

    class IVisitable {
      public:
      virtual void
      accept(IVisitor& visitor)
          = 0;
      virtual ~IVisitable() = default;
    };

  }  // namespace common
}  // namespace sgx