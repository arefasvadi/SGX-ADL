
#pragma once

#include "BlockHeader.h"
#include "CacheEngine.hpp"
#include "IBlockable.h"
#include "enclave_t.h"
#include "sgx_error.h"
#include <array>
#include <functional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include "common.h"
#include "util.h"


#define BLOCK_ENGINE_INIT_FOR_LOOP(blocked_bf_var, valid_range_var,            \
                                   block_val_ptr_var, TYPE_)                   \
  auto valid_range_var = blocked_bf_var->GetEmptyValidRangeData();             \
  TYPE_ *block_val_ptr_var = nullptr;

#define BLOCK_ENGINE_COND_CHECK_FOR_LOOP_1D(blocked_bf_var, valid_range_var,   \
                                            block_val_ptr_var, is_write,       \
                                            current_index_var, i_look)         \
  int64_t current_index_var = blocked_bf_var->nDIndexToFlattend({{i_look}});   \
  if (current_index_var < valid_range_var.block_begin_ind ||                   \
      current_index_var > valid_range_var.block_end_ind) {                     \
    if (valid_range_var.block_requested_ind >= 0) {                            \
      blocked_bf_var->unlockBlock(valid_range_var.block_requested_ind);        \
    }                                                                          \
    block_val_ptr_var = blocked_bf_var->GetItemAt(current_index_var,           \
                                                  valid_range_var, is_write);  \
  }

#define BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(blocked_bf_var, valid_range_var,   \
                                            block_val_ptr_var, is_write,       \
                                            current_index_var, ilook, jlook)   \
  int64_t current_index_var =                                                  \
      blocked_bf_var->nDIndexToFlattend({{ilook, jlook}});                     \
  if (current_index_var < valid_range_var.block_begin_ind ||                   \
      current_index_var > valid_range_var.block_end_ind) {                     \
    if (valid_range_var.block_requested_ind >= 0) {                            \
      blocked_bf_var->unlockBlock(valid_range_var.block_requested_ind);        \
    }                                                                          \
    block_val_ptr_var = blocked_bf_var->GetItemAt(current_index_var,           \
                                                  valid_range_var, is_write);  \
  }

#define BLOCK_ENGINE_LAST_UNLOCK(blocked_bf_var, valid_range_var)              \
  if (valid_range_var.block_requested_ind >= 0) {                              \
    blocked_bf_var->unlockBlock(valid_range_var.block_requested_ind);          \
  }

namespace sgx {
namespace trusted {
namespace std = ::std;

template <typename T, int Axis> class BlockedBuffer;

template <typename T, int Axis> class Block : public IBlockable {
public:
  Block(size_t num_items, bool locked);
  static std::shared_ptr<Block<T, Axis>> GetInstance(size_t num_items,
                                                     bool locked);
  using IBlockable::GetNextBlockID;

  /*inline*/ T *GetItemAt(size_t index, size_t *valid_len);
  /*inline*/ T *const GetItemAt(size_t index);

  std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE> &
  GetAllBlockContents();

  void SetAllBlockContents(
      const std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE>
          &new_block);

  ~Block() = default;

private:
  // std::array<T,MAX_PER_BLOCK_BUFFER_SIZE> val_;
  size_t numItems;
  std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE> vals_;
};

template <typename T, int Axis>
Block<T, Axis>::Block(size_t num_items, bool locked)
    : IBlockable(locked), numItems(num_items), vals_() {}

template <typename T, int Axis>
std::shared_ptr<Block<T, Axis>> Block<T, Axis>::GetInstance(size_t num_items,
                                                            bool locked) {
  return std::make_shared<Block<T, Axis>>(num_items, locked);
}

template <typename T, int Axis>
T *Block<T, Axis>::GetItemAt(size_t index, size_t *valid_len) {
  *valid_len = numItems - index;
  return &vals_[index];
}
template <typename T, int Axis>
T *const Block<T, Axis>::GetItemAt(size_t index) {
  return &vals_[index];
}

template <typename T, int Axis>
std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE> &
Block<T, Axis>::GetAllBlockContents() {
  return vals_;
}

template <typename T, int Axis>
void Block<T, Axis>::SetAllBlockContents(
    const std::array<T, BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE>
        &new_block) {
  vals_ = new_block;
}

template <typename T, int Axis> class BlockedBuffer {
public:
  using BlockValidRangeType = struct {
    int64_t block_begin_ind = -1;
    int64_t block_end_ind = -1;
    int64_t block_requested_ind = -1;
  };

  // unfortunately make shared cannot have access to private constructors!
  explicit BlockedBuffer(const std::vector<int64_t> &dim_size);
  ~BlockedBuffer() = default;

  T *GetItemAt(const int64_t &index, BlockValidRangeType &valid_range,
               bool write);
  T *const GetItemAt(const std::array<int64_t, Axis> &index, bool write);
  void GenerateBlocks();
  void unlockBlock(const int64_t &index);

  static std::shared_ptr<BlockedBuffer<T, Axis>>
  MakeBlockedBuffer(const std::vector<int64_t> &dim_size);

  static BlockValidRangeType GetEmptyValidRangeData();
  std::vector<int64_t> GetDimSize();
  int64_t GetTotalElements();
  /*inline*/ int64_t nDIndexToFlattend(const std::array<int64_t, Axis> &index);
  /*inline*/ std::array<int64_t, Axis> flattenedIndextoND(int64_t index);

  static constexpr size_t MAX_PER_BLOCK_BUFFER_SIZE_BYTES = 8 * ONE_KB;
  static constexpr size_t MAX_PER_BLOCK_BUFFER_SIZE =
      MAX_PER_BLOCK_BUFFER_SIZE_BYTES / sizeof(T);

private:
  // should first check the cache
  std::shared_ptr<IBlockable> ReadBlockFromUntrusted(const int64_t block_id);
  // first tries to write to the cache
  void WriteBlockToUntrusted(const int64_t block_id,
                             const std::shared_ptr<IBlockable> &block);

  T *GetItemAtBlock(int64_t block_id, int64_t index, size_t *valid_len);
  T *const GetItemAtBlock(int64_t block_id, int64_t index);

  std::shared_ptr<BlockHeader>
  calculateBlockHeader(std::array<T, MAX_PER_BLOCK_BUFFER_SIZE> &block_content);

  std::vector<int64_t> dimSize;
  // std::vector<int64_t> dimOrder;
  #ifdef CACHE_LRU
  LRUCache<int64_t, IBlockable> &blockCache_;
  #else
  FIFOCache<int64_t, IBlockable> &blockCache_;
  #endif
  std::unordered_map<int64_t, std::shared_ptr<BlockHeader>> headers_;
  std::vector<int64_t> orderedBlocks_;
  // TODO Later check maybe a vector of bool could be more efficient
  std::unordered_set<int64_t> changedBlocks_;

  SecStrategy secStrategy_;
  int64_t totalElements_;
  int64_t expectedBlocks_;
  int64_t lastBlockUsed_;
#ifdef CACHE_LRU
  LRUCache<int64_t, IBlockable>::EvictionHandlerType evictHdl_;
  LRUCache<int64_t, IBlockable>::ReadHandlerType readHdl_;
#else
  FIFOCache<int64_t, IBlockable>::EvictionHandlerType evictHdl_;
  FIFOCache<int64_t, IBlockable>::ReadHandlerType readHdl_;
#endif
};

template <typename T, int Axis>
BlockedBuffer<T, Axis>::BlockedBuffer(const std::vector<int64_t> &dim_size)
    : dimSize(dim_size), 
    #ifdef CACHE_LRU
    blockCache_(LRUCache<int64_t, IBlockable>::GetInstance(
                             BLOCKING_TOTAL_ITEMS_IN_CACHE)),
    #else
    blockCache_(FIFOCache<int64_t, IBlockable>::GetInstance(
                             BLOCKING_TOTAL_ITEMS_IN_CACHE)),
    #endif
      headers_(), orderedBlocks_(), changedBlocks_(),
      secStrategy_(SecStrategy::PLAIN), totalElements_(), expectedBlocks_(),
      lastBlockUsed_(0),
      evictHdl_(std::bind(&BlockedBuffer<T, Axis>::WriteBlockToUntrusted, this,
                          std::placeholders::_1, std::placeholders::_2)),
      readHdl_(std::bind(&BlockedBuffer<T, Axis>::ReadBlockFromUntrusted, this,
                         std::placeholders::_1)) {
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

template <typename T, int Axis>
std::vector<int64_t> BlockedBuffer<T, Axis>::GetDimSize() {
  return dimSize;
}
template <typename T, int Axis>
int64_t BlockedBuffer<T, Axis>::GetTotalElements() {
  return totalElements_;
}

template <typename T, int Axis>
typename BlockedBuffer<T, Axis>::BlockValidRangeType
BlockedBuffer<T, Axis>::GetEmptyValidRangeData() {
  return BlockValidRangeType();
}

template <typename T, int Axis> void BlockedBuffer<T, Axis>::GenerateBlocks() {
  totalElements_ = 1;
  int d1, d2;
  for (d1 = Axis - 1; d1 >= 0; d1--) {
    totalElements_ *= dimSize[d1];
  }

  expectedBlocks_ =
      totalElements_ / BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE;
  lastBlockUsed_ =
      totalElements_ % BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE;
  if (lastBlockUsed_ != 0) {
    expectedBlocks_++;
  }

  for (int i = 0; i < expectedBlocks_; ++i) {
    // decltype(&Block<T, Axis>::GetInstance) block;
    std::shared_ptr<Block<T, Axis>> block;
    if (i == expectedBlocks_ - 1 && lastBlockUsed_ != 0) {
      block = Block<T, Axis>::GetInstance(lastBlockUsed_, false);
    } else {
      block = Block<T, Axis>::GetInstance(
          BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE, false);
    }

    auto block_id = Block<T, Axis>::GetNextBlockID();
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
    blockCache_.Put(block_id, blockable, evictHdl_);
    //blockCache_.EvictN(1);
  }
}

template <typename T, int Axis>
std::shared_ptr<BlockHeader> BlockedBuffer<T, Axis>::calculateBlockHeader(
    std::array<T, MAX_PER_BLOCK_BUFFER_SIZE> &block_content) {
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
  // here we are sure of the type!
  std::shared_ptr<Block<T, Axis>> casted_block =
      std::static_pointer_cast<Block<T, Axis>>(block);
  auto &val_ = casted_block->GetAllBlockContents();
  // auto a = val_.size();
  // we need to encrypt

  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  res = ocall_write_block(block_id, 0, (unsigned char *)&(val_[0]),
                          val_.size() * sizeof(val_[0]));
  if (res != SGX_SUCCESS) {
    printf("ocall write block caused problem! the error is "
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
  // decltype(&Block<T, Axis>::GetInstance) block;
  std::shared_ptr<Block<T, Axis>> block;
  if (block_id == orderedBlocks_[expectedBlocks_ - 1] && lastBlockUsed_ != 0) {
    block = Block<T, Axis>::GetInstance(lastBlockUsed_, false);
  } else {
    block = Block<T, Axis>::GetInstance(
        BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE, false);
  }
  auto &val_ = block->GetAllBlockContents();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  res = ocall_read_block(block_id, 0, (unsigned char *)&val_[0],
                         val_.size() * sizeof(val_[0]));
  if (res != SGX_SUCCESS) {
    printf("ocall read block caused problem! the error is "
           "%#010X \n",
           res);
    abort();
  }

  std::shared_ptr<IBlockable> casted_block = block;
  return casted_block;
}

template <typename T, int Axis>
T *const
BlockedBuffer<T, Axis>::GetItemAt(const std::array<int64_t, Axis> &index,
                                  bool write) {

  int64_t flattened_index = nDIndexToFlattend(index);

  auto block_id =
      orderedBlocks_[flattened_index /
                     BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE];
  if (write) {
    changedBlocks_.insert(block_id);
  }
  return GetItemAtBlock(block_id,
                        flattened_index %
                            BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE);
}

template <typename T, int Axis>
T *BlockedBuffer<T, Axis>::GetItemAt(const int64_t &index,
                                     BlockValidRangeType &valid_range,
                                     bool write) {
  // https://stackoverflow.com/a/20994371/1906041

  auto block_number = index / BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE;
  if (!(block_number>=0 && block_number < orderedBlocks_.size())) {
    LOG_DEBUG("Undesired situation for block number %d where it can only be in [%d,%d]\n",block_number,0,orderedBlocks_.size()-1)
    auto aaa = 1;
  }
  auto block_id = orderedBlocks_[block_number];
  auto index_in_block =
      index % BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE;
  LOG_TRACE("About to get index %ld in block %ld\n", index_in_block, block_id);
  // LOG_DEBUG("About to get index %ld in block
  // %ld\n",index_in_block,block_id); LOG_DEBUG("About to get item %ld in
  // block %ld\n",index_in_block,block_id);
  if (write) {
    changedBlocks_.insert(block_id);
  }
  size_t valid_len = 0;
  T *item = GetItemAtBlock(block_id, index_in_block, &valid_len);
  LOG_TRACE("loaded item %ld in block %ld with value %f\n", index_in_block,
            block_id, (double)(*item));
  valid_range.block_begin_ind = index - index_in_block;
  valid_range.block_end_ind = index + valid_len - 1;
  valid_range.block_requested_ind = index;
  return item;
}

template <typename T, int Axis>
T *const BlockedBuffer<T, Axis>::GetItemAtBlock(int64_t block_id,
                                                int64_t index) {
  auto &block = blockCache_.Get(block_id, evictHdl_, readHdl_);
  block->setLocked(true);
  std::shared_ptr<Block<T, Axis>> casted_block =
      std::static_pointer_cast<Block<T, Axis>>(block);
  return casted_block->GetItemAt(index);
}

template <typename T, int Axis>
T *BlockedBuffer<T, Axis>::GetItemAtBlock(int64_t block_id, int64_t index,
                                          size_t *valid_len) {
  auto &block = blockCache_.Get(block_id, evictHdl_, readHdl_);
  block->setLocked(true);
  std::shared_ptr<Block<T, Axis>> casted_block =
      std::static_pointer_cast<Block<T, Axis>>(block);
  return casted_block->GetItemAt(index, valid_len);
}
template <typename T, int Axis>
void BlockedBuffer<T, Axis>::unlockBlock(const int64_t &index) {
  LOG_TRACE("Blocked Buffer UnlockBlock invoked with index: %ld\n", index);
  auto block_id =
      orderedBlocks_[index / BlockedBuffer<T, Axis>::MAX_PER_BLOCK_BUFFER_SIZE];
  auto &block = blockCache_.Get(block_id, evictHdl_, readHdl_);
  block->setLocked(false);
  LOG_TRACE("Blocked Buffer UnlockBlock finished for index: %ld\n", index);
}

template <typename T, int Axis>
int64_t BlockedBuffer<T, Axis>::nDIndexToFlattend(
    const std::array<int64_t, Axis> &index) {
  // https://stackoverflow.com/a/20994371/1906041

  int64_t flattened_index = 0;
  int64_t mul = 1;
  for (int64_t i = Axis - 1; i >= 0; --i) {
    flattened_index += index[i] * mul;
    mul *= dimSize[i];
  }
  if (flattened_index >=totalElements_ || flattened_index <0)  {
    LOG_ERROR("Wrong nD index requested to be flattened.\n%d is out of bound for [0-%d]\n",flattened_index,totalElements_)
    abort();
  }
  return flattened_index;
}

template <typename T, int Axis>
std::array<int64_t, Axis>
BlockedBuffer<T, Axis>::flattenedIndextoND(int64_t index) {
  if (index >=totalElements_ || index <0)  {
    LOG_ERROR("Wrong flattened index requested.\n%d is out of bound for [0-%d]\n",index,totalElements_)
    abort();
  }
  std::array<int64_t, Axis> indexes;
  size_t mul = totalElements_;
  for (int64_t i = 0; i < Axis; ++i) {
    mul /= dimSize[i];
    indexes[i] = index / mul;
    index -= indexes[i] * mul;
  }
  return indexes;
}

// template class BlockedBuffer<float, 1>;
// template class BlockedBuffer<float, 2>;
// template class BlockedBuffer<double, 1>;
// template class BlockedBuffer<double, 2>;
}; // namespace trusted
}; // namespace sgx