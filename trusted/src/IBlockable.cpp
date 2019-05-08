#include "IBlockable.h"

namespace sgx {
namespace trusted {

IBlockable::IBlockable(bool locked) : locked_(locked) {}
int64_t IBlockable::NextBlockIDStart = 0;

} // namespace sgx
} // namespace trusted