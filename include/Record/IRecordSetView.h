#pragma once

#include "Record/IRecord.h"

namespace sgx {
  namespace trusted {
    class IRecordSetView {
      public:
      virtual ~IRecordSetView() = default;

      virtual size_t
      getRecordSetID() const = 0;

      virtual void
      prepare(size_t view_size)
          = 0;

      // indices refer to the recordset
      virtual void
      getItemsFromRecordSet(const std::vector<size_t>& indices)
          = 0;

      // indices refer to the recordset
      virtual void
      getItemsInRangeFromRecordSet(const size_t i, const size_t len)
          = 0;

      // indices refer to the recordset
      virtual void
      sendItemsToRecordSet(const std::vector<size_t>& indices)
          = 0;

      // indices refer to the recordset
      virtual void
      setItemsInRangeFromRecordSet(const size_t i, const size_t len)
          = 0;

      virtual void
      cleanUp()
          = 0;

      // indices refer to the view
      virtual std::unique_ptr<common::IRecord>&
      getItemAt(const size_t i_view)
          = 0;

      // indices refer to the view
      virtual std::vector<uint8_t>
      getItemAtSerialized(const size_t i_view) const = 0;

      // indices refer to the view
      virtual std::vector<uint8_t>
      getItemsInRangeSerialized(const size_t i_view,
                                const size_t len) const = 0;
      // indices refer to the view
      virtual std::vector<uint8_t>
      getItmesIndicesSerialized(
          const std::vector<size_t>& indices_view) const = 0;

      // indices refer to the view
      virtual void
      setItemAt(const size_t                       i_view,
                std::unique_ptr<common::IRecord>&& changed_record)
          = 0;

      // indices refer to the view
      virtual void
      setItemAtSerialized(const size_t           i_view,
                          std::vector<uint8_t>&& changed_record) const = 0;

      // indices refer to the view
      virtual void
      setItemsInRangeSerialized(
          const size_t           i_view,
          const size_t           len,
          std::vector<uint8_t>&& change_records) const = 0;

      // indices refer to the view
      virtual void
      setItmesIndicesSerialized(
          const std::vector<size_t>& indices_view,
          std::vector<uint8_t>&&     changed_records) const = 0;

      virtual common::RecordTypes
      getRecordsType() const = 0;

      protected:
      IRecordSetView() = default;

      private:
    };
  }  // namespace trusted
}  // namespace sgx