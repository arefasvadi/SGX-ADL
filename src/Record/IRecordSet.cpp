#include "Record/IRecordSet.h"

namespace sgx {
  namespace untrusted {

    size_t IRecordSet::currentID_ = 0;

    std::unordered_map<size_t, std::unique_ptr<IRecordSet>>
        IRecordSet::recSetReg_;

    void
    IRecordSet::addToRegistery(std::unique_ptr<IRecordSet>&& record_set) {
      recSetReg_[record_set->getRecordSetID()] = std::move(record_set);
    }

    std::unique_ptr<IRecordSet>
    IRecordSet::removeFromRegistery(const size_t id) {
      auto rec = std::move(recSetReg_[id]);
      recSetReg_.erase(id);
      return rec;
    }

    std::unique_ptr<IRecordSet>&
    IRecordSet::getFromRegistery(const size_t id) {
      return recSetReg_[id];
    }
  }  // namespace untrusted
}  // namespace sgx