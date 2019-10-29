#include "Record/ImageRecord.h"

#include <Visitors/Visitor.h>

#include <cstring>
#include <string>

namespace sgx {
  namespace common {

    ImageRecord::ImageRecord() : img_(0){};

    ImageRecord::ImageRecord(int width, int height, int channels) :
        img_((width * height * channels),0.0) {
      img_.shrink_to_fit();
    }

    std::vector<uint8_t>
    ImageRecord::serializeFromThis() const {
      std::vector<uint8_t> res(getRecordSizeInBytes());
      res.shrink_to_fit();
      std::memcpy(res.data(), (uint8_t*)img_.data(), res.size());
      return res;
    }

    void
    ImageRecord::serializeFromThis(uint8_t*     buff,
                                   const size_t start_ind,
                                   const size_t len) const {
      if (start_ind + len > this->getRecordSizeInBytes()) {
        throw std::runtime_error(
            "start_ind and len do not match the underlying vector");
      }
      std::memcpy(buff, (uint8_t*)img_.data() + start_ind, len);
    }

    void
    ImageRecord::unSerializeIntoThis(std::vector<uint8_t>&& serialized) {
      if (serialized.size() != getRecordSizeInBytes()) {
        throw std::runtime_error(
            "size of the source and destination for unserializing does not "
            "match!\n");
      }
      std::memcpy((uint8_t*)img_.data(), serialized.data(), serialized.size());
    }

    void
    ImageRecord::unSerializeIntoThis(uint8_t*     buff,
                                     const size_t start_ind,
                                     const size_t len) {
      if (start_ind + len > this->getRecordSizeInBytes()) {
        throw std::runtime_error(
            "start_ind and len do not match the underlying vector");
      }
      std::memcpy((uint8_t*)img_.data() + start_ind, buff, len);
    }

    size_t
    ImageRecord::getRecordSizeInBytes() const {
      return img_.size() * sizeof(float);
    }

    const std::string
    ImageRecord::to_string() const {
      std::string res = "\"image contents\":\n[";
      const auto  len = img_.size();
      for (auto i = uint64_t{0}; i < len; ++i) {
        res += std::to_string(img_[i]) + ",";
      }
      res.back() = ']';
      res += "\"";
      return res;
    }

    std::vector<uint8_t>
    ImageRecord::fullySerialize() const {
      const auto&          content_size = getRecordSizeInBytes();
      std::vector<uint8_t> res(sizeof(RecordTypes) + sizeof(content_size)
                               + content_size);
      res.shrink_to_fit();
      // use the buffered version
      const auto my_type = this->myType();
      std::memcpy(res.data(), &my_type, sizeof(my_type));
      std::memcpy(
          res.data() + sizeof(my_type), &content_size, sizeof(content_size));
      serializeFromThis(
          res.data() + sizeof(my_type) + sizeof(content_size), 0, content_size);
      return res;
    }

    void
    ImageRecord::fullyUnserialize(std::vector<uint8_t>&& fully_serialized) {
      RecordTypes* type = (RecordTypes*)fully_serialized.data();
      if (*type != this->myType()) {
        throw std::runtime_error("type mismatch\n");
      }
      size_t content_size = 0;
      std::memcpy(&content_size,
                  fully_serialized.data() + sizeof(RecordTypes),
                  sizeof(size_t));
      img_.resize(content_size / sizeof(float));
      img_.shrink_to_fit();
      unSerializeIntoThis(
          &fully_serialized[sizeof(RecordTypes) + sizeof(content_size)],
          0,
          content_size);
    }

    // ImageRecord*
    // ImageRecord::clone_impl() const {
    //   return new ImageRecord(*this);
    // }

    void
    ImageRecord::accept(IVisitor& visitor) {
      visitor.visit(*this);
    }

  }  // namespace common
}  // namespace sgx