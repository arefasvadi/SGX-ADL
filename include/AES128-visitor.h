#pragma once
#include "Record/Visitor.h"

namespace sgx {
  namespace common {
    
    class IRecord;

    class AES128Visitor : public Visitor {
      virtual void
      visit(IVisitable& visitable) override;

      virtual void
      visit(IRecord& visitable) override;
    }
  }  // namespace common
}  // namespace sgx
