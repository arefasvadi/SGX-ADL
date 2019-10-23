#pragma once
#include <memory>
#include <vector>

#include "Security/IAuthenticatedIntegrity.h"
#include "Security/IEncryption.h"
#include "Security/IIntegrity.h"
#include "Security/ISignature.h"
#include "Visitors/IVisitable.h"
#include "common.h"

namespace sgx {
  namespace common {

    typedef enum class RecordTypes {
      UNKNOWN_REC = 0,
      IMAGE_REC = 1000,
      IMAGE_W_ID_REC = 1100,
      LABEL_REC = 2000,
      LABEL_W_ID_REC = 2100,
      IMAGE_W_LABEL_REC = 3000,
      IMAGE_W_LABEL_W_ID_REC = 3100,

    } RecordTypes;

    std::string
    RecordTypeToString(RecordTypes t);
    RecordTypes
    stringToRecordType(const std::string& t);

    class IRecord : public IVisitable {
      public:
      virtual ~IRecord() = default;

      DISALLOW_COPY_AND_ASSIGN(IRecord);
      ALLOW_DEFAULT_MOVE_NOEXCEPT(IRecord);

      virtual std::vector<uint8_t>
      serializeFromThis() const = 0;

      virtual void
      serializeFromThis(uint8_t*     buff,
                        const size_t start_ind,
                        const size_t len) const = 0;

      virtual void
      unSerializeIntoThis(std::vector<uint8_t>&& serialized)
          = 0;

      virtual void
      unSerializeIntoThis(uint8_t*     buff,
                          const size_t start_ind,
                          const size_t len)
          = 0;

      virtual size_t
      getRecordSizeInBytes() const = 0;

      virtual const std::string
      to_string() const = 0;

      // for file storage
      virtual std::vector<uint8_t>
      fullySerialize() const = 0;

      // for file storage
      virtual void
      fullyUnserialize(std::vector<uint8_t>&& fully_serialized) = 0;

      virtual RecordTypes
      myType() const
          = 0;
      // std::unique_ptr<IRecord>
      // clone() const;

      protected:
      IRecord() = default;
      // virtual IRecord* clone_impl() const = 0;
      private:
    };

    class IRecordDecorator : public IRecord {
      public:
      virtual ~IRecordDecorator() = default;
      ALLOW_DEFAULT_MOVE_NOEXCEPT(IRecordDecorator);

      virtual const std::unique_ptr<IRecord>&
      getDecorated() const {
        return this->IRecPtr_;
      };

      protected:
      explicit IRecordDecorator(std::unique_ptr<IRecord>&& irec_ptr) :
          IRecord(), IRecPtr_(std::move(irec_ptr)){};

      // IRecordDecorator(const IRecordDecorator&);

      // DISALLOW_ASSIGN(IRecordDecorator);
      // IRecordDecorator&
      // operator=(const IRecordDecorator&);
      // ALLOW_DEFAULT_MOVE_NOEXCEPT(IRecordDecorator);

      // virtual IRecordDecorator * clone_impl() const override;
      std::unique_ptr<IRecord> IRecPtr_;

      private:
    };

    class IRecordWID : public IRecordDecorator {
      public:
      virtual ~IRecordWID() = default;

      explicit IRecordWID(const size_t               id,
                          std::unique_ptr<IRecord>&& irec_ptr) :
          IRecordDecorator(std::move(irec_ptr)),
          ID_(id){};

      ALLOW_DEFAULT_MOVE_NOEXCEPT(IRecordWID);

      virtual size_t
      getRecordID() const {
        return ID_;
      };

      protected:
      private:
      size_t ID_;
    };

    class IEncRecord : public IRecordDecorator {
      public:
      virtual ~IEncRecord() = default;

      virtual void
      encrypPlainIntoThis()
          = 0;
      virtual void
      decryptThisIntoPlain()
          = 0;

      protected:
      using IRecordDecorator::IRecPtr_;
      std::shared_ptr<IEncryption> IEncPtr_;

      private:
    };

    class IIntegRecord : public IRecordDecorator {
      public:
      virtual ~IIntegRecord() = default;

      virtual void
      digestPlainIntoThis()
          = 0;
      virtual void
      verifyDigestPutIntoPlain()
          = 0;

      protected:
      using IRecordDecorator::IRecPtr_;
      std::shared_ptr<IIntegrity> IIntegPtr_;

      private:
    };

    class IAuthRecord : public IRecordDecorator {
      public:
      virtual ~IAuthRecord() = default;

      virtual void
      AuthPlainIntoThis()
          = 0;
      virtual void
      verifyAuthPutIntoPlain()
          = 0;

      protected:
      using IRecordDecorator::IRecPtr_;
      std::shared_ptr<IAutheticatedIntegrity> IAuthPtr_;

      private:
    };

    class ISignedRecord : public IRecordDecorator {
      public:
      virtual ~ISignedRecord() = default;
      virtual void
      SignPlainIntoThis()
          = 0;
      virtual void
      verifySignPutIntoPlain()
          = 0;

      protected:
      using IRecordDecorator::IRecPtr_;
      std::shared_ptr<ISignature> ISignPtr_;

      private:
    };

    class IEncWAuthRecord :
        virtual public IEncRecord,
        virtual public IAuthRecord {
      public:
      virtual ~IEncWAuthRecord() = default;

      protected:
      using IAuthRecord::IAuthPtr_;
      using IEncRecord::IEncPtr_;
      using IRecordDecorator::IRecPtr_;

      private:
    };

    class IEncWSignRecord :
        virtual public IEncRecord,
        virtual public ISignedRecord {
      public:
      virtual ~IEncWSignRecord() = default;

      protected:
      using IEncRecord::IEncPtr_;
      using IRecordDecorator::IRecPtr_;
      using ISignedRecord::ISignPtr_;

      private:
    };

  }  // namespace common
}  // namespace sgx
