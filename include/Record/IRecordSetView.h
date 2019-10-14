#pragma once

#include "Record/IRecord.h"

namespace sgx {
  namespace common {
    class IRecordSetView {
      public:
      virtual ~IRecordSetView() = default;
      explicit IRecordSetView(const size_t rec_set_id) :
          recordSetID_(rec_set_id){};

      virtual void
      prepareItemsFromRecordSet(const std::vector<const size_t>& indices)
          = 0;

      virtual void
      persistItemsToRecordSet(const std::vector<const size_t>& indices)
          = 0;

      virtual const std::unique_ptr<IRecord>&
      getItemAt(const size_t index) const = 0;

      virtual std::unique_ptr<IRecord>&
      getItemAt(const size_t index)
          = 0;

      protected:
      const size_t recordSetID_;

      private:
    };
  }  // namespace common
}  // namespace sgx