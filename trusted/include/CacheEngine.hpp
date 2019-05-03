#pragma once

#include "common.h"
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include "enclave-app.h"
#include "enclave_t.h"
namespace sgx {
namespace trusted {

namespace std = ::std;

template <typename K, typename V> class ICacheable {
public:
  using EvictionHandlerType =
      std::function<void(const K &, const std::shared_ptr<V> &)>;
  using ReadHandlerType = std::function<std::shared_ptr<V>(const K &)>;

  virtual void Put(const K &key, const std::shared_ptr<V> &item,
                   const EvictionHandlerType &evict_hdl,
                   const ReadHandlerType &read_hdl) = 0;

  virtual const std::shared_ptr<V> &Get(const K &key,
                                        const EvictionHandlerType &evict_hdl,
                                        const ReadHandlerType &read_hdl) = 0;

  // completely evicts the cache;
  virtual void Evict() = 0;

  // makes room to accomodate n items of type V*;
  virtual void EvictN(int64_t n) = 0;

  virtual void Delete(const K &key) = 0;

  virtual ~ICacheable(){};

protected:
  ICacheable() = default;
};

template <typename K, typename V> class Cache;
template <typename K, typename V> class MakeCacheFinal {
private:
  MakeCacheFinal() = default;
  friend class Cache<K, V>;
};

template <typename K, typename V>
class Cache : public ICacheable<K, V>, virtual MakeCacheFinal<K, V> {
public:
  using EvictionHandlerType = typename ICacheable<K, V>::EvictionHandlerType;
  using ReadHandlerType = typename ICacheable<K, V>::ReadHandlerType;

  ~Cache() = default;

  inline void Put(const K &key, const std::shared_ptr<V> &item,
           const EvictionHandlerType &evict_hdl,
           const ReadHandlerType &read_hdl) override;
  inline const std::shared_ptr<V> &Get(const K &key,
                                const EvictionHandlerType &evict_hdl,
                                const ReadHandlerType &read_hdl) override;
  void Evict() override;
  void EvictN(int64_t n) override;
  void Delete(const K &key) override;
  std::size_t GetTotalElements();
  static Cache<K, V> &GetInstance(std::size_t total_elements);

private:
  explicit Cache(std::size_t total_elements);

  std::size_t totalAllowedElements_;
  std::unordered_map<K, std::shared_ptr<V>> cache_;
  std::unordered_map<K, uint64_t> blockLastTimer_;
  std::map<uint64_t, K> timer_;
  std::unordered_map<K, std::pair<EvictionHandlerType, ReadHandlerType>>
      handlers_;
  uint64_t lastAccess_;
};

template <typename K, typename V>
Cache<K, V> &Cache<K, V>::GetInstance(std::size_t total_elements) {
  static Cache<K, V> instance(total_elements);
  return instance;
}

template <typename K, typename V>
Cache<K, V>::Cache(std ::size_t total_elements)
    : ICacheable<K, V>(), totalAllowedElements_(total_elements), cache_(),
      blockLastTimer_(), timer_(), handlers_(), lastAccess_(0) {}

template <typename K, typename V> std::size_t Cache<K, V>::GetTotalElements() {
  return cache_.size();
}

template <typename K, typename V>
void Cache<K, V>::Put(const K &key, const std::shared_ptr<V> &item,
                      const EvictionHandlerType &evict_hdl,
                      const ReadHandlerType &read_hdl) {
  if (cache_.size() == totalAllowedElements_) {
    EvictN(1);
  }
  lastAccess_++;
  if (lastAccess_ == 0) {
    // reset everything since counter is maxed out
    Evict();
    lastAccess_ = 1;
  }
  cache_[key] = item;
  auto it_last_access = blockLastTimer_.find(key);
  if (it_last_access != blockLastTimer_.end()) {
    timer_.erase(it_last_access->second);
  }
  blockLastTimer_[key] = lastAccess_;
  timer_[lastAccess_] = key;
  handlers_[key] =
      std::pair<EvictionHandlerType, ReadHandlerType>(evict_hdl, read_hdl);
}

template <typename K, typename V>
const std::shared_ptr<V> &Cache<K, V>::Get(const K &key,
                                           const EvictionHandlerType &evict_hdl,
                                           const ReadHandlerType &read_hdl) {
  //const char *timee =  "cache get";
  //ocall_set_timing(timee,strlen(timee)+1, 1,0);
  if (cache_.find(key) == cache_.end()) {
    auto read_block = read_hdl(key);
    Put(key, read_block, evict_hdl, read_hdl);
  }
  //ocall_set_timing(timee,strlen(timee)+1, 0,0);
  return cache_[key];
}

template <typename K, typename V> void Cache<K, V>::Delete(const K &key) {
  // my_printf("Delete was invoked\n");
  handlers_[key].first(key, cache_[key]);
  cache_.erase(key);
  const auto last_access = blockLastTimer_[key];
  timer_.erase(last_access);
  blockLastTimer_.erase(key);
}

template <typename K, typename V> void Cache<K, V>::Evict() {
  EvictN(cache_.size());
}

template <typename K, typename V> void Cache<K, V>::EvictN(int64_t n) {
  while (--n >= 0) {
    auto it = timer_.begin();
    if (it != timer_.end()) {
      Delete(it->second);
    }
  }
}
}; // namespace trusted
}; // namespace sgx