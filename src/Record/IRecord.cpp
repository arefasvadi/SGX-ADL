#include "Record/IRecord.h"

namespace sgx {
  namespace common {

    // std::unique_ptr<IRecord>
    // IRecord::clone() const {
    //   return std::unique_ptr<IRecord>(clone_impl());
    // }

    // IRecordDecorator * IRecordDecorator::clone_impl() const {
    //     return new IRecordDecorator(*this);
    // }

    // IRecordDecorator::IRecordDecorator(const IRecordDecorator& other) :
    //     IRecPtr_(other.IRecPtr_->clone()) {
    // }

    // IRecordDecorator&
    // IRecordDecorator::operator=(const IRecordDecorator& other) {
    //   if (&other != this) {
    //   }
    //   return *this;
    // }

    std::string
    RecordTypeToString(RecordTypes t) {
      if (t == RecordTypes::IMAGE_REC) {
        return std::string("IMAGE_REC");
      } else if (t == RecordTypes::IMAGE_W_ID_REC) {
        return std::string("IMAGE_W_ID_REC");
      } else if (t == RecordTypes::LABEL_REC) {
        return std::string("LABEL_REC");
      } else if (t == RecordTypes::LABEL_W_ID_REC) {
        return std::string("LABEL_W_ID_REC");
      } else if (t == RecordTypes::IMAGE_W_LABEL_REC) {
        return std::string("IMAGE_W_LABEL_REC");
      } else if (t == RecordTypes::IMAGE_W_LABEL_W_ID_REC) {
        return std::string("IMAGE_W_LABEL_W_ID_REC");
      }
      throw std::runtime_error("This record type is unknow!");
    }

    RecordTypes
    stringToRecordType(const std::string& t) {
      if (t == std::string("IMAGE_REC")) {
        return RecordTypes::IMAGE_REC;
      } else if (t == std::string("IMAGE_W_ID_REC")) {
        return RecordTypes::IMAGE_W_ID_REC;
      } else if (t == std::string("LABEL_REC")) {
        return RecordTypes::LABEL_REC;
      } else if (t == std::string("LABEL_W_ID_REC")) {
        return RecordTypes::LABEL_W_ID_REC;
      } else if (t == std::string("IMAGE_W_LABEL_REC")) {
        return RecordTypes::IMAGE_W_LABEL_REC;
      } else if (t == std::string("IMAGE_W_LABEL_W_ID_REC")) {
        return RecordTypes::IMAGE_W_LABEL_W_ID_REC;
      }
      throw std::runtime_error("This record type is unknow!");
    }
  }  // namespace common
}  // namespace sgx