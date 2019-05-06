#pragma once

#include "common.h"
#include "enclave-app.h"
#include "enclave_t.h"
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>

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

template <typename K, typename V> class Cache;
template <typename K, typename V> class MakeCacheFinal {
private:
  MakeCacheFinal() = default;
  friend class Cache<K, V>;
};

// FIFO implementation
template <typename K, typename V>
class Cache : public ICacheable<K, V>, virtual MakeCacheFinal<K, V> {
public:
  using EvictionHandlerType = typename ICacheable<K, V>::EvictionHandlerType;
  using ReadHandlerType = typename ICacheable<K, V>::ReadHandlerType;

  ~Cache() = default;

  inline void Put(const K &key, const std::shared_ptr<V> &item,
                  const EvictionHandlerType &evict_hdl) override;
  inline const std::shared_ptr<V> &
  Get(const K &key, const EvictionHandlerType &evict_hdl,
      const ReadHandlerType &read_hdl) override;
  void Evict() override;
  void EvictN(int64_t n) override;
  void Delete(const K &key, bool &success) override;
  std::size_t GetTotalElements();
  static Cache<K, V> &GetInstance(std::size_t total_elements);

private:
  explicit Cache(std::size_t total_elements);

  std::size_t totalAllowedElements_;
  std::unordered_map<K, std::tuple<std::shared_ptr<V>, EvictionHandlerType>>
      cache_;
  // std::unordered_map<K, std::shared_ptr<V>> cache_;
  // std::unordered_map<K, uint64_t> blockLastTimer_;
  std::map<uint64_t, K> timer_;
  // std::unordered_map<K, EvictionHandlerType> handlers_;
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
      /*blockLastTimer_(),*/ timer_(), /*handlers_(),*/ lastAccess_(0) {}

/* template <typename K, typename V> Cache<K, V>::~Cache() {
  // causes segmentation fault!
  Evict();
} */

template <typename K, typename V> std::size_t Cache<K, V>::GetTotalElements() {
  return cache_.size();
}

template <typename K, typename V>
void Cache<K, V>::Put(const K &key, const std::shared_ptr<V> &item,
                      const EvictionHandlerType &evict_hdl) {
  if (cache_.size() == totalAllowedElements_) {
    EvictN(1);
  }

  // const auto &key_it = cache_.find(key);
  // if (key_it == cache_.cend()) {
  lastAccess_++;
  /* if (lastAccess_ == 0) {
    // reset everything since counter is maxed out
    Evict();
    lastAccess_ = 1;
  } */
  cache_[key] =
      std::tuple<std::shared_ptr<V>, EvictionHandlerType>(item, evict_hdl);
  timer_[lastAccess_] = key;
  return;
  //}

  // std::get<0>(key_it->second) = item;
  // timer_[lastAccess_] = key;
}

template <typename K, typename V>
const std::shared_ptr<V> &Cache<K, V>::Get(const K &key,
                                           const EvictionHandlerType &evict_hdl,
                                           const ReadHandlerType &read_hdl) {
  // const char *timee =  "cache get";
  // ocall_set_timing(timee,strlen(timee)+1, 1,0);
  const auto &key_it = cache_.find(key);
  if (key_it == cache_.cend()) {
    Put(key, std::move(read_hdl(key)), evict_hdl);
    return std::get<0>(cache_[key]);
  }
  return std::get<0>(key_it->second);
  // ocall_set_timing(timee,strlen(timee)+1, 0,0);
}

template <typename K, typename V> void Cache<K, V>::Delete(const K &key, bool &success) {
  // my_printf("Delete was invoked\n");
  const auto &key_it = cache_.find(key);
  // calls the wrie to untrusted!
  if (std::get<0>(key_it->second)->isLocked()){
    success = false;
    return;
  }
  std::get<1>(key_it->second)(key, std::get<0>(key_it->second));
  cache_.erase(key_it);
  // blockLastTimer_.erase(key);
}

template <typename K, typename V> void Cache<K, V>::Evict() {
  EvictN(cache_.size());
}

template <typename K, typename V> void Cache<K, V>::EvictN(int64_t n) {
  while (--n >= 0) {
    const auto &it = timer_.cbegin();
    if (it != timer_.cend()) {
      bool success = true;
      Delete(it->second,success);
      if (success)
        timer_.erase(it);
      else {
        ++n;
      }
    }
  }
}
}; // namespace trusted
}; // namespace sgx