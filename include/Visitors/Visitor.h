#pragma once

namespace sgx {
  namespace common {

    class IVisitable;
    class RecordVisitor;
    class ImageRecord;
    class ImageWLabelRecord;

    class IVisitor {
      public:
      virtual ~IVisitor() = default;
      virtual void
      visit(IVisitable& visitable){};
      virtual void
      visit(ImageRecord& visitable){};
      virtual void
      visit(ImageWLabelRecord& visitable){};
    };

    class RecordVisitor : virtual public IVisitor {
      virtual void
      visit(IVisitable& visitable) override;
      virtual void
      visit(ImageRecord& visitable) override;
    };
  }  // namespace common
}  // namespace sgx