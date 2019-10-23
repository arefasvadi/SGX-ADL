#pragma once

#include "Record/IRecordSetView.h"

namespace sgx {
  namespace trusted {
    class VectorRecordSetView : public IRecordSetView {
      public:
      virtual ~VectorRecordSetView() = default;

      explicit VectorRecordSetView(const size_t record_set_id,
                                   const size_t current_view_size,
                                   const size_t total_records) :
          IRecordSetView(record_set_id, current_view_size, total_records){};

      virtual void
      prepare(size_t view_size) override;

      // indices refer to the recordset
      virtual void
      getItemsFromRecordSet(const std::vector<size_t>& indices) override;

      // indices refer to the recordset
      virtual void
      getItemsInRangeFromRecordSet(const size_t i, const size_t len) override;

      // indices refer to the recordset
      virtual void
      sendItemsToRecordSet(const std::vector<size_t>& indices) override;

      // indices refer to the recordset
      virtual void
      setItemsInRangeFromRecordSet(const size_t i, const size_t len) override;

      virtual void
      cleanUp() override;

      // indices refer to the view
      virtual std::unique_ptr<common::IRecord>&
      getItemAt(const size_t i_view) override;

      // indices refer to the view
      virtual std::vector<uint8_t>
      getItemAtSerialized(const size_t i_view) const override;

      // indices refer to the view
      virtual std::vector<uint8_t>
      getItemsInRangeSerialized(const size_t i_view,
                                const size_t len) const override;
      // indices refer to the view
      virtual std::vector<uint8_t>
      getItmesIndicesSerialized(
          const std::vector<size_t>& indices_view) const override;

      // indices refer to the view
      virtual void
      setItemAt(const size_t                       i_view,
                std::unique_ptr<common::IRecord>&& changed_record) override;

      // indices refer to the view
      virtual void
      setItemAtSerialized(const size_t           i_view,
                          std::vector<uint8_t>&& changed_record) const override;

      // indices refer to the view
      virtual void
      setItemsInRangeSerialized(
          const size_t           i_view,
          const size_t           len,
          std::vector<uint8_t>&& change_records) const override;

      // indices refer to the view
      virtual void
      setItmesIndicesSerialized(
          const std::vector<size_t>& indices_view,
          std::vector<uint8_t>&&     changed_records) const override;

      protected:
        std::vector<std::unique_ptr<common::IRecord>> viewStorage_;
        
      private:
    };
  }  // namespace trusted
}  // namespace sgx