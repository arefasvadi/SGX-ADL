#include "Record/VectorRecordSet.h"
#include "Visitors/Visitor.h"
#include "cassert"

namespace sgx {
  namespace untrusted {
    VectorRecordSet::VectorRecordSet(std::string               name,
                                     const common::RecordTypes r_type,
                                     size_t                    initial_sz) :
        VectorRecordSet(name) {
      storage_.reserve(initial_sz);
      recType_ = r_type;
    };

    const std::unique_ptr<common::IRecord>&
    VectorRecordSet::getItemAt(const size_t i) const {
      assert((i >= 0 && i < storage_.size()));
      return storage_[i];
    }

    std::vector<uint8_t>
    VectorRecordSet::getItemAtSerialized(const size_t i) const {
      assert((i >= 0 && i < storage_.size()));
      return storage_[i]->serializeFromThis();
    }

    std::vector<uint8_t>
    VectorRecordSet::getItemsInRangeSerialized(const size_t i,
                                               const size_t len) const {
      assert((i >= 0 && (i + len) <= storage_.size()));
      std::vector<uint8_t> res;
      for (size_t ind = i; ind < len; ++ind) {
        auto vec = storage_[ind]->serializeFromThis();
        std::copy(vec.begin(), vec.end(), std::back_inserter(res));
      }
      return res;
    }

    std::vector<uint8_t>
    VectorRecordSet::getIndicesSerialized(
        const std::vector<size_t>& indices) const {
      std::vector<uint8_t> res;
      for (const auto i : indices) {
        assert((i >= 0 && i < storage_.size()));
        auto vec = storage_[i]->serializeFromThis();
        std::copy(vec.begin(), vec.end(), std::back_inserter(res));
      }
      return res;
    }

    void
    VectorRecordSet::setItemAt(
        const size_t i, std::unique_ptr<common::IRecord>&& changed_record) {
      assert((i >= 0 && i < storage_.size()));
      storage_[i] = std::move(changed_record);
    }

    void
    VectorRecordSet::setItemAtSerialized(
        const size_t i, std::vector<uint8_t>&& changed_record) {
      assert((i >= 0 && i < storage_.size()));
      storage_[i]->unSerializeIntoThis(std::move(changed_record));
    }

    void
    VectorRecordSet::setItemsInRangeSerialized(
        const size_t           i,
        const size_t           len,
        std::vector<uint8_t>&& changed_records) {
      assert((i >= 0 && (i + len) <= storage_.size()));
      size_t loc = 0;
      for (size_t ind = i; ind < len; ++ind) {
        size_t rec_size = storage_[ind]->getRecordSizeInBytes();
        storage_[ind]->unSerializeIntoThis(&changed_records[loc], 0, rec_size);
        loc += rec_size;
      }
    }

    void
    VectorRecordSet::setIndicesSerialized(
        const std::vector<size_t>& indices,
        std::vector<uint8_t>&&     changed_records) {
      size_t loc = 0;
      for (const auto i : indices) {
        assert((i >= 0 && i < storage_.size()));
        size_t rec_size = storage_[i]->getRecordSizeInBytes();
        storage_[i]->unSerializeIntoThis(&changed_records[loc], 0, rec_size);
        loc += rec_size;
      }
    }

    std::unique_ptr<common::IRecord>
    VectorRecordSet::removeAt(const size_t i) {
      assert((i >= 0 && i < storage_.size()));
      auto it = storage_.begin();
      std::advance(it, i);
      auto rec = std::move(*it);
      storage_.erase(it);
      return rec;
    }

    void
    VectorRecordSet::appendNew(std::unique_ptr<common::IRecord>&& new_record) {
      storage_.push_back(std::move(new_record));
    }

    void
    VectorRecordSet::persistThisToFile(const std::string& file_path) const {
      throw std::runtime_error("This function not implemented yet!");
    }

    void
    VectorRecordSet::loadFileIntoThis(const std::string& file_path) {
      throw std::runtime_error("This function not implemented yet!");
    }

    const std::string
    VectorRecordSet::to_string() const {
      std::string res = "\"Vectorized RecordSet\" with ID: "
                        + std::to_string(getRecordSetID()) + "\n{\"";
      for (const auto& r : storage_) {
        res += r->to_string() + ";";
      }

      res += "\"}\n";
      return res;
    }

    size_t
    VectorRecordSet::getTotalNumberofElements() const {
      return storage_.size();
    }

    size_t
    VectorRecordSet::getRecordSetSizeInBytes() const {
      size_t total_bytes = 0;
      for (const auto& r : storage_) {
        total_bytes += r->getRecordSizeInBytes();
      }
      return total_bytes;
    }

    common::RecordTypes
    VectorRecordSet::getRecordsType() const {
      return recType_;
    }

    void
    VectorRecordSet::accept(common::IVisitor& visitor) {
        visitor.visit(*this);
    }

  }  // namespace untrusted
}  // namespace sgx