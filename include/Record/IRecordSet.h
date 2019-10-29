#pragma once
#include <memory>
#include <unordered_map>

#include "Record/IRecord.h"
#include "Visitors/IVisitable.h"

namespace sgx {
  namespace untrusted {

    class IRecordSet : public common::IVisitable {
      public:
      virtual ~IRecordSet() = default;

      size_t
      getRecordSetID() const {
        return this->ID_;
      };

      virtual const std::unique_ptr<common::IRecord>&
      getItemAt(const size_t i) const = 0;

      virtual std::vector<uint8_t>
      getItemAtSerialized(const size_t i) const = 0;

      virtual std::vector<uint8_t>
      getItemsInRangeSerialized(const size_t i, const size_t len) const = 0;

      virtual std::vector<uint8_t>
      getIndicesSerialized(const std::vector<size_t>& indices) const = 0;

      virtual void
      setItemAt(const size_t                       i,
                std::unique_ptr<common::IRecord>&& changed_record)
          = 0;

      virtual void
      setItemAtSerialized(const size_t i, std::vector<uint8_t>&& changed_record)
          = 0;

      virtual void
      setItemsInRangeSerialized(const size_t           i,
                                const size_t           len,
                                std::vector<uint8_t>&& changed_records)
          = 0;

      virtual void
      setIndicesSerialized(const std::vector<size_t>& indices,
                           std::vector<uint8_t>&&     changed_records)
          = 0;

      virtual std::unique_ptr<common::IRecord>
      removeAt(const size_t i) = 0;

      virtual void
      appendNew(std::unique_ptr<common::IRecord>&& new_record)
          = 0;

      virtual void
      persistThisToFile(const std::string& file_path) const = 0;

      virtual void
      loadFileIntoThis(const std::string& file_path)
          = 0;

      virtual const std::string
      to_string() const = 0;

      virtual size_t
      getTotalNumberofElements() const = 0;

      virtual size_t
      getRecordSetSizeInBytes() const = 0;

      virtual common::RecordTypes
      getRecordsType() const = 0;

      static void
      addToRegistery(std::unique_ptr<IRecordSet>&& record_set);

      static std::unique_ptr<IRecordSet>
      removeFromRegistery(const size_t id);

      static std::unique_ptr<IRecordSet>&
      getFromRegistery(const size_t id);

      protected:
      explicit IRecordSet(std::string name) :
          ID_(++currentID_), name_(std::move(name)){};

      private:
      static size_t                                                  currentID_;
      static std::unordered_map<size_t, std::unique_ptr<IRecordSet>> recSetReg_;

      const size_t      ID_;
      const std::string name_;
    };
  }  // namespace untrusted
}  // namespace sgx