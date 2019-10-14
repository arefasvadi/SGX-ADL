#include "Record/ImageWithLabelRecord.h"
#include <Visitors/Visitor.h>
#include <cstring>
#include <string>
#include "Record/ImageRecord.h"

namespace sgx {
  namespace common {
    ImageWLabelRecord::ImageWLabelRecord(
        int num_classes, std::unique_ptr<ImageRecord>&& image_ptr) :
        IRecordDecorator(std::move(image_ptr)),
        label_(num_classes) {
    }

    // ImageWLabelRecord::ImageWLabelRecord(const ImageWLabelRecord& rhs) :
    //     IRecordDecorator(rhs.IRecPtr_->clone()), label_(rhs.label_) {
    // }

    // ImageWLabelRecord&
    // ImageWLabelRecord::operator=(const ImageWLabelRecord& rhs) {
    //   if (this != &rhs) {

    //   }
    //   return *this;
    // }

    std::vector<uint8_t>
    ImageWLabelRecord::serializeFromThis() const {
      std::vector<uint8_t> res = IRecPtr_->serializeFromThis();
      res.resize(this->getRecordSizeInBytes());
      res.shrink_to_fit();
      std::memcpy(res.data() + IRecPtr_->getRecordSizeInBytes(),
                  (uint8_t*)label_.data(),
                  label_.size() * sizeof(float));
      return res;
    }

    void
    ImageWLabelRecord::serializeFromThis(uint8_t*     buff,
                                         const size_t start_ind,
                                         const size_t len) const {
      if (start_ind + len > this->getRecordSizeInBytes()) {
        throw std::runtime_error(
            "start_ind and len do not match the underlying vector");
      }
      const auto   whose_index   = this->getWhoseIndex(start_ind, len);
      const size_t decorated_len = this->IRecPtr_->getRecordSizeInBytes();

      if (whose_index == WhoseIndex::shared) {
        this->IRecPtr_->serializeFromThis(
            buff, start_ind, decorated_len - start_ind);
        std::memcpy(buff + (decorated_len - start_ind),
                    (uint8_t*)this->label_.data(),
                    len - (decorated_len - start_ind));

      } else if (whose_index == WhoseIndex::mine) {
        std::memcpy(buff,
                    (uint8_t*)this->label_.data() + (start_ind - decorated_len),
                    len);
      } else if (whose_index == WhoseIndex::childs) {
        this->IRecPtr_->serializeFromThis(buff, start_ind, len);
      }
    }

    void
    ImageWLabelRecord::unSerializeIntoThis(std::vector<uint8_t> serialized) {
      if (serialized.size() != getRecordSizeInBytes()) {
        throw std::runtime_error(
            "size of the source and destination for unserializing does not "
            "match!\n");
      }

      std::memcpy((uint8_t*)label_.data(),
                  serialized.data() + IRecPtr_->getRecordSizeInBytes(),
                  label_.size() * sizeof(float));
      serialized.resize(IRecPtr_->getRecordSizeInBytes());
      serialized.shrink_to_fit();
      IRecPtr_->unSerializeIntoThis(std::move(serialized));
    }

    void
    ImageWLabelRecord::unSerializeIntoThis(uint8_t*     buff,
                                           const size_t start_ind,
                                           const size_t len) {
      if (start_ind + len > this->getRecordSizeInBytes()) {
        throw std::runtime_error(
            "start_ind and len do not match the underlying vector");
      }

      const auto   whose_index   = this->getWhoseIndex(start_ind, len);
      const size_t decorated_len = this->IRecPtr_->getRecordSizeInBytes();

      if (whose_index == WhoseIndex::shared) {
        this->IRecPtr_->serializeFromThis(
            buff, start_ind, decorated_len - start_ind);
        std::memcpy((uint8_t*)this->label_.data(),
                    buff + (decorated_len - start_ind),
                    len - (decorated_len - start_ind));

      } else if (whose_index == WhoseIndex::mine) {
        std::memcpy((uint8_t*)this->label_.data() + (start_ind - decorated_len),
                    buff,
                    len);
      } else if (whose_index == WhoseIndex::childs) {
        this->IRecPtr_->serializeFromThis(buff, start_ind, len);
      }
    }

    const size_t
    ImageWLabelRecord::getRecordSizeInBytes() const {
      return this->IRecPtr_->getRecordSizeInBytes()
             + (sizeof(float) * label_.size());
    }

    const std::string
    ImageWLabelRecord::to_string() const {
      std::string res = IRecPtr_->to_string();
      res += "\n\"label contents\":\n[";
      const auto len = label_.size();
      for (int i = 0; i < len; ++i) {
        res += std::to_string(label_[i]) + ",";
      }
      res.back() = ']';
      res += "\"";
      return res;
    }

    // ImageWLabelRecord*
    // ImageWLabelRecord::clone_impl() const {
    //   return new ImageWLabelRecord(*this);
    // }

    void
    ImageWLabelRecord::accept(IVisitor& visitor) {
      visitor.visit(*this);
    }

    const ImageWLabelRecord::WhoseIndex
    ImageWLabelRecord::getWhoseIndex(const size_t start_ind,
                                     const size_t len) const {
      const size_t decorated_len = this->IRecPtr_->getRecordSizeInBytes();

      const bool index_is_childs         = (start_ind + len) <= (decorated_len);
      const bool index_is_mine           = (start_ind >= decorated_len);
      const bool index_is_shared_w_child = !index_is_mine && !index_is_childs;
      if (index_is_childs)
        return WhoseIndex::childs;
      else if (index_is_mine)
        return WhoseIndex::mine;
      else if (index_is_shared_w_child)
        return WhoseIndex::shared;

      throw std::runtime_error("Index cannot be matched properly!");
    }

  }  // namespace common
}  // namespace sgx