#pragma once
#include "common.h"

#include <vector>
#include "Record/IRecord.h"

namespace sgx {
  namespace common {
    class ImageRecord : virtual public IRecord {
      public:
      virtual ~ImageRecord() = default;
      explicit ImageRecord(int width, int height, int channels);

      // ALLOW_DEFAULT_COPY_AND_ASSIGN(ImageRecord);
      ALLOW_DEFAULT_MOVE_NOEXCEPT(ImageRecord);

      virtual std::vector<uint8_t>
      serializeFromThis() const override;

      virtual void
      serializeFromThis(uint8_t*     buff,
                        const size_t start_ind,
                        const size_t len) const override;

      virtual void
      unSerializeIntoThis(std::vector<uint8_t> serialized) override;

      virtual void
      unSerializeIntoThis(uint8_t*     buff,
                          const size_t start_ind,
                          const size_t len) override;

      virtual const size_t
      getRecordSizeInBytes() const override;

      virtual const std::string
      to_string() const override;

      virtual void
      accept(IVisitor& visitor) override;

      // virtual ImageRecord*
      // clone_impl() const override;

      protected:
      private:
      std::vector<float> img_;
    };

    class ImageRecordWID : virtual public IRecordWID {
      public:
      explicit ImageRecordWID(const size_t                 id,
                              std::unique_ptr<ImageRecord> irec_ptr) :
          IRecordWID(id, std::move(irec_ptr)){};

      protected:
      private:
    };

  }  // namespace common
}  // namespace sgx