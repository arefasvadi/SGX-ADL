#pragma once
#include <memory>
#include <vector>

#include "Record/IRecord.h"
#include "common.h"

namespace sgx {
  namespace common {
    class ImageRecord;

    class ImageWLabelRecord : virtual public IRecordDecorator {
      public:
      virtual ~ImageWLabelRecord() = default;

      explicit ImageWLabelRecord(int                            num_classes,
                                 std::unique_ptr<ImageRecord>&& image_ptr);

      // ALLOW_DEFAULT_COPY(ImageWLabelRecord);
      // ImageWLabelRecord(const ImageWLabelRecord&);

      // ImageWLabelRecord& operator=(const ImageWLabelRecord&);
      // DISALLOW_ASSIGN(ImageWLabelRecord);

      // ALLOW_DEFAULT_MOVE_AND_ASSIGN_NOEXCEPT(ImageWLabelRecord);
      ALLOW_DEFAULT_MOVE_NOEXCEPT(ImageWLabelRecord);

      virtual std::vector<uint8_t>
      serializeFromThis() const override;

      virtual void
      serializeFromThis(uint8_t*     buff,
                        const size_t start_ind,
                        const size_t len) const override;

      virtual void
      unSerializeIntoThis(std::vector<uint8_t>&& serialized) override;

      virtual void
      unSerializeIntoThis(uint8_t*     buff,
                          const size_t start_ind,
                          const size_t len) override;

      virtual size_t
      getRecordSizeInBytes() const override;

      virtual const std::string
      to_string() const override;

      virtual std::vector<uint8_t>
      fullySerialize() const override;

      virtual void
      fullyUnserialize(std::vector<uint8_t>&& fully_serialized) override;

      virtual RecordTypes
      myType() const override {
        return RecordTypes::IMAGE_W_LABEL_REC;
      };

      // virtual ImageWLabelRecord*
      // clone_impl() const override;

      virtual void
      accept(IVisitor& visitor) override;

      protected:
      private:
      enum class WhoseIndex { mine = 0, childs = 1, shared = 2 };

      WhoseIndex
                         getWhoseIndex(const size_t start_ind, const size_t len) const;
      std::vector<float> label_;
    };

    class ImageWLabelWIDRecord : virtual public IRecordWID {
      public:
      explicit ImageWLabelWIDRecord(
          const size_t id, std::unique_ptr<ImageWLabelRecord> irec_ptr) :
          IRecordWID(id, std::move(irec_ptr)){};
      ALLOW_DEFAULT_MOVE_NOEXCEPT(ImageWLabelWIDRecord);

      protected:
      private:
    };

  }  // namespace common
}  // namespace sgx