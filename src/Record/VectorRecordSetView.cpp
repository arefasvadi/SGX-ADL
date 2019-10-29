#include "Record/VectorRecordSetView.h"
namespace sgx {
  namespace trusted {
    namespace {
//#define USE_SGX
#ifdef USE_SGX
      //   std::vector<uint8_t>
      //   getItemFromRecSetHandler(size_t rec_set_id, size_t index) {
      //     std::vector<uint8_t> res;
      //     // call to an ocall to get the fully serialized with its size

      //     return res;
      //   }
#else
#endif
    }  // namespace

    VectorRecordSetView::VectorRecordSetView(
        const size_t              record_set_id,
        const size_t              current_view_size,
        const size_t              total_records,
        const common::RecordTypes rec_type) :
        IRecordSetView(),
        recordSetID_(record_set_id), currentViewSize_(current_view_size),
        totalRecords_(total_records), recType_(rec_type),
        viewStorage_(currentViewSize_){};

    size_t
    VectorRecordSetView::getRecordSetID() const {
      return recordSetID_;
    }

    void
    VectorRecordSetView::prepare(size_t view_size) {
        this->currentViewSize_ = view_size;
        this->viewStorage_.resize(view_size);
    };

    // indices refer to the recordset
    void
    VectorRecordSetView::getItemsFromRecordSet(
        const std::vector<size_t>& indices){

    };

    // indices refer to the recordset
    void
    VectorRecordSetView::getItemsInRangeFromRecordSet(const size_t i,
                                                      const size_t len){};

    // indices refer to the recordset
    void
    VectorRecordSetView::sendItemsToRecordSet(
        const std::vector<size_t>& indices){};

    // indices refer to the recordset
    void
    VectorRecordSetView::setItemsInRangeFromRecordSet(const size_t i,
                                                      const size_t len){};

    void
    VectorRecordSetView::cleanUp() {
      this->viewStorage_.clear();
      this->currentViewSize_ = 0;
      // keep the capacity!
    };

    // indices refer to the view
    std::unique_ptr<common::IRecord>&
    VectorRecordSetView::getItemAt(const size_t i_view){};

    // indices refer to the view
    std::vector<uint8_t>
    VectorRecordSetView::getItemAtSerialized(const size_t i_view) const {};

    // indices refer to the view
    std::vector<uint8_t>
    VectorRecordSetView::getItemsInRangeSerialized(const size_t i_view,
                                                   const size_t len) const {};
    // indices refer to the view
    std::vector<uint8_t>
    VectorRecordSetView::getItmesIndicesSerialized(
        const std::vector<size_t>& indices_view) const {};

    // indices refer to the view
    void
    VectorRecordSetView::setItemAt(
        const size_t                       i_view,
        std::unique_ptr<common::IRecord>&& changed_record){};

    // indices refer to the view
    void
    VectorRecordSetView::setItemAtSerialized(
        const size_t i_view, std::vector<uint8_t>&& changed_record) const {};

    // indices refer to the view
    void
    VectorRecordSetView::setItemsInRangeSerialized(
        const size_t           i_view,
        const size_t           len,
        std::vector<uint8_t>&& change_records) const {};

    // indices refer to the view
    void
    VectorRecordSetView::setItmesIndicesSerialized(
        const std::vector<size_t>& indices_view,
        std::vector<uint8_t>&&     changed_records) const {};

    common::RecordTypes
    VectorRecordSetView::getRecordsType() const {
      return recType_;
    }
  }  // namespace trusted
}  // namespace sgx