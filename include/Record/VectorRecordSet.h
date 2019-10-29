#pragma once
#include <vector>

#include "Record/IRecordSet.h"

namespace sgx {
  namespace untrusted {

    class VectorRecordSet : public IRecordSet {
      public:
      virtual ~VectorRecordSet() = default;
      explicit VectorRecordSet(std::string         name,
                               common::RecordTypes r_type,
                               size_t              initial_sz);

      virtual const std::unique_ptr<common::IRecord>&
      getItemAt(const size_t i) const override;

      virtual std::vector<uint8_t>
      getItemAtSerialized(const size_t i) const override;

      virtual std::vector<uint8_t>
      getItemsInRangeSerialized(const size_t i,
                                const size_t len) const override;

      virtual std::vector<uint8_t>
      getIndicesSerialized(const std::vector<size_t>& indices) const override;

      virtual void
      setItemAt(const size_t                       i,
                std::unique_ptr<common::IRecord>&& changed_record) override;

      virtual void
      setItemAtSerialized(const size_t           i,
                          std::vector<uint8_t>&& changed_record) override;

      virtual void
      setItemsInRangeSerialized(
          const size_t           i,
          const size_t           len,
          std::vector<uint8_t>&& changed_records) override;

      virtual void
      setIndicesSerialized(const std::vector<size_t>& indices,
                           std::vector<uint8_t>&&     changed_records) override;

      virtual std::unique_ptr<common::IRecord>
      removeAt(const size_t i) override;

      virtual void
      appendNew(std::unique_ptr<common::IRecord>&& new_record) override;

      virtual void
      persistThisToFile(const std::string& file_path) const override;

      virtual void
      loadFileIntoThis(const std::string& file_path) override;

      virtual const std::string
      to_string() const override;

      virtual size_t
      getTotalNumberofElements() const override;

      virtual size_t
      getRecordSetSizeInBytes() const override;

      virtual common::RecordTypes
      getRecordsType() const override;

      virtual void
      accept(common::IVisitor& visitor) override;

      protected:
      explicit VectorRecordSet(std::string name) : IRecordSet(name){};
      std::vector<std::unique_ptr<common::IRecord>> storage_;
      common::RecordTypes                           recType_;

      private:
    };
  }  // namespace untrusted
}  // namespace sgx