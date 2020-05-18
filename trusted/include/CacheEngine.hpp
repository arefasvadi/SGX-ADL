#pragma once

#include "common.h"
#include "enclave-app.h"
#include "enclave_t.h"
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include "util.h"

namespace sgx {
namespace trusted {

namespace std = ::std;

template <typename K, typename V> class ICacheable {
public:
  using EvictionHandlerType =
      std::function<void(const K &, const std::shared_ptr<V> &)>;
  using ReadHandlerType = std::function<std::shared_ptr<V>(const K &)>;

  virtual void Put(const K &key, const std::shared_ptr<V> &item,
                   const EvictionHandlerType &evict_hdl) = 0;

  virtual const std::shared_ptr<V> &Get(const K &key,
                                        const EvictionHandlerType &evict_hdl,
                                        const ReadHandlerType &read_hdl) = 0;

  // completely evicts the cache;
  virtual void Evict() = 0;

  // makes room to accomodate n items of type V*;
  virtual void EvictN(int64_t n) = 0;

  virtual void Delete(const K &key, bool &success) = 0;

  virtual ~ICacheable(){};

protected:
  ICacheable() = default;
};

template <typename K, typename V> class FIFOCache;
template <typename K, typename V> class LRUCache;
template <typename K, typename V> class MakeCacheFinal {
private:
  MakeCacheFinal() = default;
  friend class FIFOCache<K, V>;
  friend class LRUCache<K, V>;
};

// FIFO implementation
template <typename K, typename V>
class FIFOCache : public ICacheable<K, V>, virtual MakeCacheFinal<K, V> {
public:
  using EvictionHandlerType = typename ICacheable<K, V>::EvictionHandlerType;
  using ReadHandlerType = typename ICacheable<K, V>::ReadHandlerType;
  using CacheListType = std::list<typename std::tuple<std::shared_ptr<V>, EvictionHandlerType,K>>;

  ~FIFOCache() = default;

  /*inline*/ void Put(const K &key, const std::shared_ptr<V> &item,
                      const EvictionHandlerType &evict_hdl) override;
  /*inline*/ const std::shared_ptr<V> &
  Get(const K &key, const EvictionHandlerType &evict_hdl,
      const ReadHandlerType &read_hdl) override;
  void Evict() override;
  void EvictN(int64_t n) override;
  void Delete(const K &key, bool &success) override;
  std::size_t GetTotalElements();
  static FIFOCache<K, V> &GetInstance(std::size_t total_elements);

private:
  explicit FIFOCache(std::size_t total_elements);

  std::size_t totalAllowedElements_;
  std::unordered_map<K,typename CacheListType::iterator> cache_;
  CacheListType fifoList_;
};

template <typename K, typename V>
FIFOCache<K, V> &FIFOCache<K, V>::GetInstance(std::size_t total_elements) {
  static FIFOCache<K, V> instance(total_elements);
  return instance;
}

template <typename K, typename V>
FIFOCache<K, V>::FIFOCache(std ::size_t total_elements)
    : ICacheable<K, V>(), totalAllowedElements_(total_elements), cache_(),
      fifoList_() {}

/* template <typename K, typename V> Cache<K, V>::~Cache() {
  // causes segmentation fault!
  Evict();
} */

template <typename K, typename V>
std::size_t FIFOCache<K, V>::GetTotalElements() {
  return cache_.size();
}

template <typename K, typename V>
void FIFOCache<K, V>::Put(const K &key, const std::shared_ptr<V> &item,
                          const EvictionHandlerType &evict_hdl) {
  LOG_TRACE("Put was invoked for key %ld\n", key);
  // LOG_DEBUG("Put was invoked for key %ld\n",key);
  if (cache_.size() == totalAllowedElements_) {
    EvictN(1);
  }
  
  fifoList_.emplace_back(std::tuple<std::shared_ptr<V>, EvictionHandlerType,K>(item, evict_hdl,key));
  cache_[key] = std::prev(fifoList_.end());
  // Due to reverse iterator issues we add new elements to back
  return;
}

template <typename K, typename V>
const std::shared_ptr<V> &
FIFOCache<K, V>::Get(const K &key, const EvictionHandlerType &evict_hdl,
                     const ReadHandlerType &read_hdl) {
  LOG_ERROR("USE SGX BLOCKING not supported\n")
  abort();
  // const char *timee =  "cache get";
  // ocall_set_timing(timee,strlen(timee)+1, 1,0);
  LOG_TRACE("Cache Get was invokded for key %ld\n", key);
  // LOG_DEBUG("Cache Get was invokded for key %ld\n",key);
  const auto &key_it = cache_.find(key);
  if (key_it == cache_.cend()) {
    //char *timee =  "Cache Miss";
    //ocall_set_timing(timee,strlen(timee)+1, 1,0);
    Put(key, std::move(read_hdl(key)), evict_hdl);
    //ocall_set_timing(timee,strlen(timee)+1, 0,0);
    return std::get<0>(*(cache_[key]));
  }

  return std::get<0>(*(key_it->second));
  // ocall_set_timing(timee,strlen(timee)+1, 0,0);
}

template <typename K, typename V>
void FIFOCache<K, V>::Delete(const K &key, bool &success) {
  // printf("Delete was invoked\n");
  LOG_TRACE("Cache Delete invoked with key: %ld\n", key);
  // LOG_DEBUG("Cache Delete invoked with key: %ld\n",key);
  const auto &key_it = cache_.find(key);
  // calls the wrie to untrusted!
  if (std::get<0>(*(key_it->second))->isLocked()) {
    LOG_TRACE("Cache Delete with key %ld was not successful due to lock!\n",
              key);
    success = false;
    return;
  }
  std::get<1>(*(key_it->second))(key, std::get<0>(*(key_it->second)));
  cache_.erase(key_it);
  // blockLastTimer_.erase(key);
}

template <typename K, typename V> void FIFOCache<K, V>::Evict() {
  EvictN(cache_.size());
}

template <typename K, typename V> void FIFOCache<K, V>::EvictN(int64_t n) {
  LOG_TRACE("Cache Eviction was invoked for total of %ld\n", n);
  // Due to reverse iterator issues we remove elements from front
  auto last_item = fifoList_.begin();
  while (n > 0 && fifoList_.end() != last_item) {
    bool success = true;
    Delete(std::get<2>(*last_item), success);
    if (success) {
      fifoList_.erase(last_item++);
      --n;
    } else {
      ++last_item;
    }
  }
}

// LRU implementation
template <typename K, typename V>
class LRUCache : public ICacheable<K, V>, virtual MakeCacheFinal<K, V> {
public:
  using EvictionHandlerType = typename ICacheable<K, V>::EvictionHandlerType;
  using ReadHandlerType = typename ICacheable<K, V>::ReadHandlerType;
  using CacheListType = std::list<typename std::tuple<std::shared_ptr<V>, EvictionHandlerType,K>>;
  ~LRUCache() = default;

  /*inline*/ void Put(const K &key, const std::shared_ptr<V> &item,
                      const EvictionHandlerType &evict_hdl) override;
  /*inline*/ const std::shared_ptr<V> &
  Get(const K &key, const EvictionHandlerType &evict_hdl,
      const ReadHandlerType &read_hdl) override;
  void Evict() override;
  void EvictN(int64_t n) override;
  void Delete(const K &key, bool &success) override;
  std::size_t GetTotalElements();
  static LRUCache<K, V> &GetInstance(std::size_t total_elements);

private:
  explicit LRUCache(std::size_t total_elements);

  std::size_t totalAllowedElements_;
  std::unordered_map<K,typename CacheListType::iterator> cache_;
  CacheListType fifoList_;
};

template <typename K, typename V>
LRUCache<K, V> &LRUCache<K, V>::GetInstance(std::size_t total_elements) {
  static LRUCache<K, V> instance(total_elements);
  return instance;
}

template <typename K, typename V>
LRUCache<K, V>::LRUCache(std ::size_t total_elements)
    : ICacheable<K, V>(), totalAllowedElements_(total_elements), cache_(),
      fifoList_() {
        //LOG_DEBUG("LRU Cache Invoked\n")
      }

/* template <typename K, typename V> Cache<K, V>::~Cache() {
  // causes segmentation fault!
  Evict();
} */

template <typename K, typename V>
std::size_t LRUCache<K, V>::GetTotalElements() {
  return cache_.size();
}

template <typename K, typename V>
void LRUCache<K, V>::Put(const K &key, const std::shared_ptr<V> &item,
                         const EvictionHandlerType &evict_hdl) {
  LOG_TRACE("Put was invoked for key %ld\n", key);
  // LOG_DEBUG("Put was invoked for key %ld\n",key);
  if (cache_.size() == totalAllowedElements_) {
    EvictN(1);
  }
  
  fifoList_.emplace_back(std::tuple<std::shared_ptr<V>, EvictionHandlerType,K>(item, evict_hdl,key));
  cache_[key] = std::prev(fifoList_.end());
  // Due to reverse iterator issues we add new elements to back
  return;
}

template <typename K, typename V>
const std::shared_ptr<V> &
LRUCache<K, V>::Get(const K &key, const EvictionHandlerType &evict_hdl,
                    const ReadHandlerType &read_hdl) {
  LOG_ERROR("USE SGX BLOCKING not supported\n")
  abort();
  // const char *timee =  "cache get";
  // ocall_set_timing(timee,strlen(timee)+1, 1,0);
  LOG_TRACE("Cache Get was invokded for key %ld\n", key);
  // LOG_DEBUG("Cache Get was invokded for key %ld\n",key);
  // char *timee =  "Cache Get";
  // ocall_set_timing(timee,strlen(timee)+1, 1,0);
  const auto &key_it = cache_.find(key);
  if (key_it == cache_.cend()) {
    // char *timee =  "Cache Miss";
    // ocall_set_timing(timee,strlen(timee)+1, 1,0);
    Put(key, std::move(read_hdl(key)), evict_hdl);
    // ocall_set_timing(timee,strlen(timee)+1, 0,0);
    return std::get<0>(*(cache_[key]));
  }

  fifoList_.splice(fifoList_.end(), fifoList_,key_it->second);
  // ocall_set_timing(timee,strlen(timee)+1, 0,0);
  return std::get<0>(*(key_it->second));
  // ocall_set_timing(timee,strlen(timee)+1, 0,0);
}

template <typename K, typename V>
void LRUCache<K, V>::Delete(const K &key, bool &success) {
  // printf("Delete was invoked\n");
  LOG_TRACE("Cache Delete invoked with key: %ld\n", key);
  // LOG_DEBUG("Cache Delete invoked with key: %ld\n",key);
  const auto &key_it = cache_.find(key);
  // calls the wrie to untrusted!
  if (std::get<0>(*(key_it->second))->isLocked()) {
    LOG_TRACE("Cache Delete with key %ld was not successful due to lock!\n",
              key);
    success = false;
    return;
  }
  std::get<1>(*(key_it->second))(key, std::get<0>(*(key_it->second)));
  cache_.erase(key_it);
  // blockLastTimer_.erase(key);
}

template <typename K, typename V> void LRUCache<K, V>::Evict() {
  EvictN(cache_.size());
}

template <typename K, typename V> void LRUCache<K, V>::EvictN(int64_t n) {
  LOG_TRACE("Cache Eviction was invoked for total of %ld\n", n);
  // Due to reverse iterator issues we remove elements from front
  auto last_item = fifoList_.begin();
  while (n > 0 && fifoList_.end() != last_item) {
    bool success = true;
    Delete(std::get<2>(*last_item), success);
    if (success) {
      fifoList_.erase(last_item++);
      --n;
    } else {
      ++last_item;
    }
  }
}

}; // namespace trusted
}; // namespace sgx