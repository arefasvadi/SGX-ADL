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
  }  // namespace common
}  // namespace sgx