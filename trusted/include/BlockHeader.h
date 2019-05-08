#pragma once
#include "common.h"
#include <vector>

namespace sgx {
namespace trusted {
namespace std = ::std;
// class BlockHeaderNullType {};

// always instantiate this class on heap
// user of the object must take care of deallocation and deleting of objects

class BlockHeader {
public:
  /* using HeaderType =
     std::variant<BlockHeaderNullType,std::array<uint8_t,AES_GCM_TAG_SIZE+AES_GCM_IV_SIZE>,
      std::array<uint8_t,AES_CMAC_TAG_SIZE>>; */
  using HeaderType = std::vector<uint8_t>;
  // static std::shared_ptr<BlockHeader<Axis>> MakeBlockHeader();

  BlockHeader(SecStrategy sec_strategy);
  ~BlockHeader() = default;
  static std::shared_ptr<BlockHeader> MakeBlockHeader(SecStrategy sec_strategy);
  HeaderType &GetHeader();
  void SetHeader(HeaderType &header);

private:
  size_t headerLen_;
  // std::pair<std::array<int64_t,Axis>,std::array<int64_t,Axis>> bounds_;
  HeaderType header_;
};
};
};