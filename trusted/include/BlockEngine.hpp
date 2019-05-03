#pragma once

#include "CacheEngine.hpp"
#include <unordered_map>
#include <utility>
#include <vector>
//#include <variant>
#include "enclave_t.h"
#include "sgx_error.h"
#include <functional>
#include <memory>
#include <stdexcept>
#include <unordered_set>

#include "common.h"

namespace sgx {
namespace trusted {
namespace std = ::std;

enum SecStrategy {
  PLAIN,
  INTEGRITY,
  CONFIDENTIALITY_INTEGRITY,
};

class IBlockable {
public:
  /*
  // first item is block ID, the rest are indices for each Axis
  virtual std::vector<int64_t> At(std::vector<int64_t> &index) = 0;
  // end_index is non-inclusive
  virtual std::vector<std::vector<int64_t>> ContigousAt(std::vector<int64_t>
  &start_index, std::vector<int64_t> &end_index) = 0;
  */
  virtual ~IBlockable(){};
  static int64_t GetNextBlockID();

protected:
  static int64_t NextBlockIDStart;
};
int64_t IBlockable::NextBlockIDStart = 0;
inline int64_t IBlockable::GetNextBlockID() {
  // int64_t ID = IBlockable::NextBlockIDStart;
  // IBlockable::NextBlockIDStart += 5000000;
  return ++IBlockable::NextBlockIDStart;
}

// class BlockHeaderNullType {};

// always instantiate this class on heap
// user of the object must take care of deallocation and deleting of objects
// template<int Axis>

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

template <typename T, int Axis> class BlockedBuffer;

template <typename T, int Axis> class Block : public IBlockable {
public:
  Block();
  static std::shared_ptr<Block<T,Axis>> GetInstance();
  using IBlockable::GetNextBlockID;

  inline T GetItemAt(size_t index);
  // non-inclusive index_end;
  // std::vector<T *> GetItemsInRange(size_t index_start, size_t index_end);

  inline void SetItemAt(size_t index, T val);
  /* void setItemsInRange(size_t index_start,
                       size_t index_end,
                       std::vector<T*>& range_vals); */

  std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE> &
  GetAllBlockContents();
  
  void SetAllBlockContents(
      std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE>
          &new_block);

  ~Block() = default;

private:
  // std::array<T,MAX_PER_BLOCK_BUFFER_SIZE> val_;
  std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE> vals_;
};

template <typename T,int Axis> Block<T,Axis>::Block() : IBlockable(), vals_() {}

template <typename T, int Axis>
std::shared_ptr<Block<T, Axis>> Block<T, Axis>::GetInstance() {
  return std::make_shared<Block<T, Axis>>();
}

template <typename T, int Axis> T Block<T, Axis>::GetItemAt(size_t index) {
  return vals_[index];
}

/* template <typename T>
std::vector<T *> Block<T>::GetItemsInRange(size_t index_start,
                                           size_t index_end) {
  std::vector<T *> range_vals;
  for (int i = index_start; i < index_end; ++i) {
    range_vals.push_back(&vals_[i]);
  }
} */

template <typename T, int Axis>
void Block<T, Axis>::SetItemAt(size_t index, T val) {
  vals_[index] = val;
}

/* template <typename T>
void Block<T>::setItemsInRange(size_t index_start,
                               size_t index_end,
                               std::vector<T*>& range_vals) {
  int c = 0;
  for (int i = index_start; i < index_end; ++i) {
    vals_[i] = *(range_vals[c++]);
  }
} */

template <typename T, int Axis>
std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE> &
Block<T, Axis>::GetAllBlockContents() {
  return vals_;
}

template <typename T, int Axis>
void Block<T, Axis>::SetAllBlockContents(
    std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE>
        &new_block) {
  vals_ = new_block;
}

template <typename T, int Axis> class BlockedBuffer {
public:
  // unfortunately make shared cannot have access to private constructors!
  explicit BlockedBuffer(const std::vector<int64_t> &dim_size);
  ~BlockedBuffer() = default;

  T GetItemAt(const std::array<int64_t, Axis> &index);
  // T& ReadItemAt(int64_t index);
  void SetItemAt(const std::array<int64_t, Axis> &index, T val);
  void GenerateBlocks();

  static std::shared_ptr<BlockedBuffer<T, Axis>>
  MakeBlockedBuffer(const std::vector<int64_t> &dim_size);

  static constexpr size_t MAX_PER_BLOCK_BUFFER_SIZE_BYTES = 64 * ONE_KB;
  static constexpr size_t MAX_PER_BLOCK_BUFFER_SIZE =
      MAX_PER_BLOCK_BUFFER_SIZE_BYTES / sizeof(T);

private:
  // should first check the cache
  std::shared_ptr<IBlockable> ReadBlockFromUntrusted(const int64_t block_id);
  // first tries to write to the cache
  void WriteBlockToUntrusted(const int64_t block_id,
                             const std::shared_ptr<IBlockable> &block);

  T GetItemAtBlock(int64_t block_id, int64_t index);
  // T& ReadItemAtBlock(int64_t block_id, int64_t index);
  void SetItemAtBlock(int64_t block_id, int64_t index, T val);

  std::shared_ptr<BlockHeader>
  calculateBlockHeader(std::array<T,MAX_PER_BLOCK_BUFFER_SIZE> &block_content);

  std::vector<int64_t> dimSize;
  // std::vector<int64_t> dimOrder;
  Cache<int64_t, IBlockable> &blockCache_;
  std::unordered_map<int64_t, std::shared_ptr<BlockHeader>> headers_;
  std::vector<int64_t> orderedBlocks_;
  // TODO Later check maybe a vector of bool could be more efficient
  std::unordered_set<int64_t> changedBlocks_;
  SecStrategy secStrategy_;
  int64_t totalElements_;
  int64_t expectedBlocks_;
  int64_t lastBlockUnused_;

  
};

template <typename T, int Axis>
BlockedBuffer<T, Axis>::BlockedBuffer(const std::vector<int64_t> &dim_size)
    : dimSize(dim_size), blockCache_(Cache<int64_t, IBlockable>::GetInstance(
                             BLOCKING_TOTAL_ITEMS_IN_CACHE)),
      headers_(), orderedBlocks_(), changedBlocks_(),
      secStrategy_(SecStrategy::PLAIN), totalElements_(), expectedBlocks_(),
      lastBlockUnused_(0) {
  if (dimSize.size() != Axis) {
    throw std::invalid_argument(
        "dimension sizes does not correspond to specifed Axis");
  }
  GenerateBlocks();
}

template <typename T, int Axis>
std::shared_ptr<BlockedBuffer<T, Axis>>
BlockedBuffer<T, Axis>::MakeBlockedBuffer(
    const std::vector<int64_t> &dim_size) {
  return std::make_shared<BlockedBuffer<T, Axis>>(dim_size);
}

template <typename T, int Axis> void BlockedBuffer<T, Axis>::GenerateBlocks() {
  totalElements_ = 1;
  int d1, d2;
  for (d1 = Axis - 1; d1 >= 0; d1--) {
    totalElements_ *= dimSize[d1];
  }

  expectedBlocks_ =
      totalElements_ / BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE;
  int64_t last_block_used =
      totalElements_ % BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE;
  if (last_block_used != 0) {
    expectedBlocks_++;
    lastBlockUnused_ =
        BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE - last_block_used;
  }

  for (int i = 0; i < expectedBlocks_; ++i) {
    auto block = Block<T,Axis>::GetInstance();
    auto block_id = Block<T,Axis>::GetNextBlockID();
    // generate header for block
    if (secStrategy_ != SecStrategy::PLAIN) {
      auto header = calculateBlockHeader(block->GetAllBlockContents());
      headers_[block_id] = header;
    }
    // since it is the first time we need to set this
    changedBlocks_.insert(block_id);
    // put the block in orderedBlocks_
    orderedBlocks_.push_back(block_id);
    // put the block in cache
    std::shared_ptr<IBlockable> blockable = block;
    blockCache_.Put(block_id, blockable,
                    std::bind(&BlockedBuffer<T, Axis>::WriteBlockToUntrusted,
                              this, std::placeholders::_1,
                              std::placeholders::_2),
                    std::bind(&BlockedBuffer<T, Axis>::ReadBlockFromUntrusted,
                              this, std::placeholders::_1));
  }
}

template <typename T, int Axis>
std::shared_ptr<BlockHeader>
BlockedBuffer<T, Axis>::calculateBlockHeader(std::array<T,MAX_PER_BLOCK_BUFFER_SIZE> &block_content) {
  return nullptr;
}

template <typename T, int Axis>
void BlockedBuffer<T, Axis>::WriteBlockToUntrusted(
    const int64_t block_id, const std::shared_ptr<IBlockable> &block) {
  // we need to write it back if it has been changed!
  if (changedBlocks_.find(block_id) == changedBlocks_.end()) {
    return;
  }

  // https://stackoverflow.com/questions/43682207/how-do-i-dynamic-upcast-and-downcast-with-smart-pointers
  // std::shared_ptr<Block<T>> casted =
  // std::dynamic_pointer_cast<Block<T>>(block);

  // here we are sure of the type!
  std::shared_ptr<Block<T,Axis>> casted_block =
      std::static_pointer_cast<Block<T,Axis>>(block);
  auto &val_ = casted_block->GetAllBlockContents();
  // we need to encrypt

  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  res = ocall_write_block(block_id, 0, (unsigned char *)&val_[0],
                          val_.size() * sizeof(val_[0]));
  if (res != SGX_SUCCESS) {
    my_printf("ocall write block caused problem! the error is "
              "%#010X \n",
              res);
    abort();
  }

  // removing it from changed blocks
  changedBlocks_.erase(block_id);
}

template <typename T, int Axis>
std::shared_ptr<IBlockable>
BlockedBuffer<T, Axis>::ReadBlockFromUntrusted(const int64_t block_id) {
  // need to decrypt

  // need to verify header

  // create a new block object

  auto block = Block<T,Axis>::GetInstance();
  auto &val_ = block->GetAllBlockContents();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  res = ocall_read_block(block_id, 0, (unsigned char *)&val_[0],
                         val_.size() * sizeof(val_[0]));
  if (res != SGX_SUCCESS) {
    my_printf("ocall read block caused problem! the error is "
              "%#010X \n",
              res);
    abort();
  }

  // removing it from changed blocks -- just in case if
  changedBlocks_.erase(block_id);

  std::shared_ptr<IBlockable> casted_block = block;
  return casted_block;
}

template <typename T, int Axis>
T BlockedBuffer<T, Axis>::GetItemAt(const std::array<int64_t, Axis> &index) {
  // https://stackoverflow.com/a/20994371/1906041
  int64_t flattened_index = 0;
  int64_t mul = 1;

  for (std::size_t i = 0; i != Axis; ++i) {
    flattened_index += index[i] * mul;
    mul *= dimSize[i];
  }

  return GetItemAtBlock(
      orderedBlocks_[flattened_index /
                     BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE],
      flattened_index % BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE);
}

template <typename T, int Axis>
void BlockedBuffer<T, Axis>::SetItemAt(const std::array<int64_t, Axis> &index,
                                       T val) {
  int64_t flattened_index = 0;
  int64_t mul = 1;

  for (std::size_t i = 0; i != Axis; ++i) {
    flattened_index += index[i] * mul;
    mul *= dimSize[i];
  }
  return SetItemAtBlock(
      orderedBlocks_[flattened_index /
                     BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE],
      flattened_index % BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE, val);
}

template <typename T, int Axis>
T BlockedBuffer<T, Axis>::GetItemAtBlock(int64_t block_id, int64_t index) {
  auto &block = blockCache_.Get(
      block_id,
      std::bind(&BlockedBuffer<T, Axis>::WriteBlockToUntrusted, this,
                std::placeholders::_1, std::placeholders::_2),
      std::bind(&BlockedBuffer<T, Axis>::ReadBlockFromUntrusted, this,
                std::placeholders::_1));
  std::shared_ptr<Block<T,Axis>> casted_block =
      std::static_pointer_cast<Block<T,Axis>>(block);
  return casted_block->GetItemAt(index);
}

template <typename T, int Axis>
void BlockedBuffer<T, Axis>::SetItemAtBlock(int64_t block_id, int64_t index,
                                            T val) {
  auto &block = blockCache_.Get(
      block_id,
      std::bind(&BlockedBuffer<T, Axis>::WriteBlockToUntrusted, this,
                std::placeholders::_1, std::placeholders::_2),
      std::bind(&BlockedBuffer<T, Axis>::ReadBlockFromUntrusted, this,
                std::placeholders::_1));

  std::shared_ptr<Block<T,Axis>> casted_block =
      std::static_pointer_cast<Block<T,Axis>>(block);
  casted_block->SetItemAt(index, val);
  changedBlocks_.insert(block_id);
}

template class BlockedBuffer<float, 1>;
template class BlockedBuffer<float, 2>;
template class BlockedBuffer<double, 1>;
template class BlockedBuffer<double, 2>;
}; // namespace trusted
}; // namespace sgx