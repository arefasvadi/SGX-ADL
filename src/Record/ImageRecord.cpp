#include "Record/ImageRecord.h"
#include <Visitors/Visitor.h>
#include <cstring>
#include <string>

namespace sgx {
  namespace common {
    ImageRecord::ImageRecord(int width, int height, int channels) :
        img_((width * height * channels)) {
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
    ImageRecord::unSerializeIntoThis(std::vector<uint8_t> serialized) {
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

    const size_t
    ImageRecord::getRecordSizeInBytes() const {
      return img_.size() * sizeof(float);
    }

    const std::string
    ImageRecord::to_string() const {
      std::string res = "\"image contents\":\n[";
      const auto  len = img_.size();
      for (int i = 0; i < len; ++i) {
        res += std::to_string(img_[i]) + ",";
      }
      res.back() = ']';
      res += "\"";
      return res;
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