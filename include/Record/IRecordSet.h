#pragma once

#include <memory>
#include "Record/IRecord.h"
#include "Visitors/IVisitable.h"

namespace sgx {
  namespace common {

    class IRecordSet : virtual public IVisitable, virtual public IRecord {
      public:
      virtual ~IRecordSet() = default;

      const size_t
      getRecordSetID() const {
        return this->ID_;
      };

      virtual const std::unique_ptr<IRecord>&
      getItemAt(const size_t i) const = 0;

      virtual const std::vector<uint8_t>
      getItemAtSerialized(const size_t i) const = 0;

      virtual const std::vector<uint8_t>
      getItemsInRangeSerialized(const size_t i, const size_t len) const = 0;

      virtual void
      setItemAt(const size_t                   i,
                const std::unique_ptr<IRecord> changed_record) const = 0;

      virtual void
      setItemAtSerialized(
          const size_t                 i,
          const std::vector<uint8_t>&& changed_record) const = 0;

      virtual void
      setItemsInRangeSerialized(
          const size_t                 i,
          const size_t                 len,
          const std::vector<uint8_t>&& changed_record) const = 0;

      virtual void
      removeAt(const size_t i)
          = 0;

      virtual void
      appendNew(const std::unique_ptr<IRecord> new_record)
          = 0;

      virtual void
      persistThisToFile(const std::string& file_path) const = 0;

      virtual void
      loadFileIntoThis(const std::string& file_path)
          = 0;

      virtual const size_t
      getTotalNumberofElements() const = 0;

      protected:
      IRecordSet(const size_t id) : ID_(id){};

      private:
      static constexpr size_t currentID_ = 0;
      const size_t            ID_;
    };
  }  // namespace common
}  // namespace sgx