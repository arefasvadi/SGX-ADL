#include "BlockHeader.h"

namespace sgx {
namespace trusted {
    namespace std = ::std;

BlockHeader::BlockHeader(SecStrategy sec_strategy) {
  if (sec_strategy == SecStrategy::INTEGRITY) {
    header_ = std::vector<uint8_t>(AES_CMAC_TAG_SIZE, 0);
  } else if (sec_strategy == SecStrategy::CONFIDENTIALITY_INTEGRITY) {
    header_ = std::vector<uint8_t>(AES_GCM_TAG_SIZE + AES_GCM_IV_SIZE, 0);
  } else {
    header_ = std::vector<uint8_t>(0);
  }
  headerLen_ = header_.size();
}

std::shared_ptr<BlockHeader>
BlockHeader::MakeBlockHeader(SecStrategy sec_strategy) {
  return std::make_shared<BlockHeader>(sec_strategy);
}

BlockHeader::HeaderType &BlockHeader::GetHeader() { return header_; }

void BlockHeader::SetHeader(BlockHeader::HeaderType &header) {
  header_ = header;
}
};
};