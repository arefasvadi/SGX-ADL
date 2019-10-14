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

    class IRecord : virtual public IVisitable {
      public:
      IRecord()          = default;
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
      unSerializeIntoThis(std::vector<uint8_t> serialized)
          = 0;

      virtual void
      unSerializeIntoThis(uint8_t*     buff,
                          const size_t start_ind,
                          const size_t len)
          = 0;

      virtual const size_t
      getRecordSizeInBytes() const = 0;

      virtual const std::string
      to_string() const = 0;

      // std::unique_ptr<IRecord>
      // clone() const;

      protected:
      // virtual IRecord* clone_impl() const = 0;

      private:
    };

    class IRecordDecorator : virtual public IRecord {
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

    class IRecordWID : virtual public IRecordDecorator {
      public:
      virtual ~IRecordWID() = default;

      explicit IRecordWID(const size_t               id,
                          std::unique_ptr<IRecord>&& irec_ptr) :
          ID_(id),
          IRecordDecorator(std::move(irec_ptr)){};

      ALLOW_DEFAULT_MOVE_NOEXCEPT(IRecordWID);

      virtual const size_t
      getRecordID() const {
        return ID_;
      };

      protected:
      private:
      size_t ID_;
    };

    class IEncRecord : virtual public IRecordDecorator {
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

    class IIntegRecord : virtual public IRecordDecorator {
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

    class IAuthRecord : virtual public IRecordDecorator {
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

    class ISignedRecord : virtual public IRecordDecorator {
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
        virtual public IRecordDecorator,
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
        virtual public IRecordDecorator,
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
