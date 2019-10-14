#pragma once
#include <vector>
#include "Record/IRecordSet.h"

namespace sgx {

  namespace common {

    class VectorRecordSet : virtual public IRecordSet {
      public:
      virtual ~VectorRecordSet() = default;

      virtual const std::unique_ptr<IRecord>&
      getItemAt(const size_t i) const override;

      virtual void
      setItemAt(const size_t                   i,
                const std::unique_ptr<IRecord> changed_record) const override;

      virtual void
      removeAt(const size_t i) override;

      virtual void
      appendNew(const std::unique_ptr<IRecord> new_record) override;

      virtual void
      persistThisToFile(const std::string& file_path) const override;

      virtual void
      loadFileIntoThis(const std::string& file_path) override;

      virtual const size_t
      getTotalNumberofElements() const override;

      protected:
      std::vector<std::unique_ptr<IRecord>> storage_;

      private:
    };
  }  // namespace common
}  // namespace sgx