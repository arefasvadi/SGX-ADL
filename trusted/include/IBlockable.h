#pragma once
#include <stdint.h>

namespace sgx {
namespace trusted {
namespace std = ::std;
class IBlockable {
public:
  /*
  // first item is block ID, the rest are indices for each Axis
  virtual std::vector<int64_t> At(std::vector<int64_t> &index) = 0;
  // end_index is non-inclusive
  virtual std::vector<std::vector<int64_t>> ContigousAt(std::vector<int64_t>
  &start_index, std::vector<int64_t> &end_index) = 0;
  */
  IBlockable(bool locked);
  virtual ~IBlockable() {};
  inline static int64_t GetNextBlockID();
  inline bool isLocked() { return locked_; }
  inline void setLocked(bool locked) { locked_ = locked; }

protected:
  static int64_t NextBlockIDStart;
  bool locked_;
};

inline int64_t IBlockable::GetNextBlockID() {
  return ++IBlockable::NextBlockIDStart;
}
}; // namespace trusted
}; // namespace sgx
