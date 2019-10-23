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
    ImageWLabelRecord::unSerializeIntoThis(std::vector<uint8_t>&& serialized) {
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

    size_t
    ImageWLabelRecord::getRecordSizeInBytes() const {
      return this->IRecPtr_->getRecordSizeInBytes()
             + (sizeof(float) * label_.size());
    }

    const std::string
    ImageWLabelRecord::to_string() const {
      std::string res = IRecPtr_->to_string();
      res += "\n\"label contents\":\n[";
      const auto len = label_.size();
      for (auto i = uint64_t{0}; i < len; ++i) {
        res += std::to_string(label_[i]) + ",";
      }
      res.back() = ']';
      res += "\"";
      return res;
    }

    std::vector<uint8_t>
    ImageWLabelRecord::fullySerialize() const {
      const auto           my_type            = this->myType();
      auto                 irec_vec           = IRecPtr_->fullySerialize();
      const size_t         my_content_size    = (sizeof(float) * label_.size());
      const size_t         image_content_size = irec_vec.size();
      std::vector<uint8_t> res(sizeof(my_type) + sizeof(size_t)
                               + my_content_size + image_content_size);
      res.shrink_to_fit();

      std::memcpy(res.data(), &my_type, sizeof(my_type));
      std::memcpy(
          res.data() + sizeof(my_type), &my_content_size, sizeof(size_t));
      std::memcpy(res.data() + sizeof(my_type) + sizeof(size_t),
                  label_.data(),
                  my_content_size);
      std::memcpy(
          res.data() + sizeof(my_type) + sizeof(size_t) + my_content_size,
          irec_vec.data(),
          image_content_size);
      return res;
    }

    void
    ImageWLabelRecord::fullyUnserialize(
        std::vector<uint8_t>&& fully_serialized) {
      RecordTypes* type = (RecordTypes*)fully_serialized.data();
      if (*type != this->myType()) {
        throw std::runtime_error("type mismatch\n");
      }
      size_t my_content_size = 0;
      std::memcpy(&my_content_size,
                  fully_serialized.data() + sizeof(RecordTypes),
                  sizeof(size_t));
      label_.resize(my_content_size / sizeof(float));
      label_.shrink_to_fit();
      std::memcpy(
          label_.data(),
          fully_serialized.data() + sizeof(RecordTypes) + sizeof(size_t),
          my_content_size);

      IRecPtr_->fullyUnserialize(
          std::vector<uint8_t>(fully_serialized.begin() + sizeof(RecordTypes)
                                   + sizeof(size_t) + my_content_size,
                               fullySerialize().end()));
    }

    // ImageWLabelRecord*
    // ImageWLabelRecord::clone_impl() const {
    //   return new ImageWLabelRecord(*this);
    // }

    void
    ImageWLabelRecord::accept(IVisitor& visitor) {
      visitor.visit(*this);
    }

    ImageWLabelRecord::WhoseIndex
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