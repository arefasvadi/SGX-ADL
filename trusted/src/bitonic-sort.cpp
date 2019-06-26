#include "bitonic-sort.h"
#include "algorithm"
#include "util.h"

namespace sgx {
namespace trusted {
// template <typename SR>
// bool BitonicSorter<SR>::doSort() {
bool BitonicSorter::doSort() {
  bitonicSort(0, arrayLen_, ascending_);

  // Evict the remaining valid cache
  printf("Sorting finsihed. Now, last eviction starts!\n");
  std::vector<uint8_t> decrypted(sizeof(trainRecordSerialized));
  std::vector<uint8_t> encrypted(sizeof(trainRecordEncrypted));
  trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(encrypted[0]);
  sgx_status_t res = SGX_ERROR_UNEXPECTED;

  for (auto iter_curr = LRUCache_.begin(); iter_curr != LRUCache_.end(); iter_curr++) {
    
    std::memcpy(&decrypted[0], &(iter_curr->second),
                sizeof(trainRecordSerialized));
    auto enc_tuple = cryptoEngine_.encrypt(decrypted);

    const auto &temp_enc = std::get<0>(enc_tuple);
    std::memcpy(&(enc_r->encData), &temp_enc[0], sizeof(trainRecordSerialized));
    const auto &temp_IV = std::get<1>(enc_tuple);
    std::memcpy((enc_r->IV), &temp_IV[0], AES_GCM_IV_SIZE);
    const auto &temp_MAC = std::get<2>(enc_tuple);
    std::memcpy((enc_r->MAC), &temp_MAC[0], AES_GCM_KEY_SIZE);

    res = ocall_set_records_encrypted(1,iter_curr->first, &encrypted[0],
                            sizeof(trainRecordEncrypted));
    CHECK_SGX_SUCCESS(res, "ocall set records caused problem!\n");
  }
  printf("Sorting eviction finsihed. Now, clearing cache!\n");
  LRUCache_.clear();
  LRUCounts_.clear();
  return true;
}

// template <typename SR>
// void BitonicSorter<SR>::bitonicSort(std::size_t low, std::size_t n, bool dir)
// {
void BitonicSorter::bitonicSort(std::size_t low, std::size_t n, bool dir) {
  if (n > 1) {
    int m = n / 2;
    bitonicSort(low, m, !dir);
    bitonicSort(low + m, n - m, dir);
    bitonicMerge(low, n, dir);
  }
}

// template <typename SR>
// void BitonicSorter<SR>::bitonicMerge(std::size_t low, std::size_t n, bool
// dir) {
void BitonicSorter::bitonicMerge(std::size_t low, std::size_t n, bool dir) {
  if (n > 1) {
    int m = greatestPowerofTwoLessThan(n);

    for (int i = low; i < low + n - m; i++) {
      prepareRecords(i, i + m);
      obliviousCompareExchange(i, i + m, dir);
    }

    bitonicMerge(low, m, dir);
    bitonicMerge(low + m, n - m, dir);
  }
}

// template <typename SR>
// inline void BitonicSorter<SR>::obliviousCompareExchange(std::size_t i,
// inline
void BitonicSorter::obliviousCompareExchange(std::size_t i, std::size_t j,
                                             bool dir) {
  // auto b_cache_size = LRUCache_.size();
  // auto b_count_size = LRUCounts_.size();

  // static int num_calls = 0;
  // sgx_status_t res = SGX_ERROR_UNEXPECTED;
  // std::vector<uint8_t> enc_payload_i(sizeof(trainRecordEncrypted));
  // std::vector<uint8_t> enc_payload_j(sizeof(trainRecordEncrypted));
  // size_t len_i;
  // size_t len_j;
  // res =
  //     ocall_get_record_sort(i, &enc_payload_i[0],
  //     sizeof(trainRecordEncrypted),
  //                           j, &enc_payload_j[0],
  //                           sizeof(trainRecordEncrypted));
  // if (res !=
  //     SGX_SUCCESS /* || (len_i == len_j && len_i =
  //     sizeof(trainRecordEncrypted)) */) {
  //   printf("ocall get record sort caused problem! the error is "
  //             "%#010X \n",
  //             res);
  //   abort();
  // }

  // trainRecordEncrypted *enc_r_i = (trainRecordEncrypted *)&enc_payload_i[0];
  // trainRecordEncrypted *enc_r_j = (trainRecordEncrypted *)&enc_payload_j[0];
  // std::vector<uint8_t> enc_data_i(sizeof(trainRecordSerialized));
  // std::memcpy(&enc_data_i[0], &(enc_r_i->encData),
  //             sizeof(trainRecordSerialized));
  // std::array<uint8_t, 12> IV_i;
  // std::memcpy(&IV_i[0], (enc_r_i->IV), AES_GCM_IV_SIZE);
  // std::array<uint8_t, 16> MAC_i;
  // std::memcpy(&MAC_i[0], (enc_r_i->MAC), AES_GCM_TAG_SIZE);

  // auto enc_tuple_i = std::make_tuple(enc_data_i, IV_i, MAC_i);
  // // printf("oblivious compared called for %d times\n",++num_calls);
  // auto decrypted_i = cryptoEngine_.decrypt(enc_tuple_i);
  // trainRecordSerialized *record_i = (trainRecordSerialized *)&decrypted_i[0];

  // std::vector<uint8_t> enc_data_j(sizeof(trainRecordSerialized));
  // std::memcpy(&enc_data_j[0], &(enc_r_j->encData),
  //             sizeof(trainRecordSerialized));
  // std::array<uint8_t, 12> IV_j;
  // std::memcpy(&IV_j[0], (enc_r_j->IV), AES_GCM_IV_SIZE);
  // std::array<uint8_t, 16> MAC_j;
  // std::memcpy(&MAC_j[0], (enc_r_j->MAC), AES_GCM_TAG_SIZE);

  // auto enc_tuple_j = std::make_tuple(enc_data_j, IV_j, MAC_j);
  // auto decrypted_j = cryptoEngine_.decrypt(enc_tuple_j);
  // trainRecordSerialized *record_j = (trainRecordSerialized *)&decrypted_j[0];

  uint8_t swap_space[sizeof(trainRecordSerialized)];
  // auto it_i = LRUCache_.find(i);
  // auto it_j = LRUCache_.find(j);
  trainRecordSerialized temp = (LRUCache_[i]);
  // if (it_i == LRUCache_.end() || it_j == LRUCache_.end()) {
  // int crappy = 0;
  // }
  // trainRecordSerialized temp = it_i->second;

  std::memcpy(&temp, &(LRUCache_[i]), sizeof(trainRecordSerialized));
  // auto cache_size = LRUCache_.size();
  // auto count_size = LRUCounts_.size();
  trainRecordSerialized *record_i = &(LRUCache_[i]);
  // trainRecordSerialized record_i = it_i->second;
  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();
  trainRecordSerialized *record_j = &(LRUCache_[j]);
  // trainRecordSerialized record_j = it_j->second;
  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  // operator> must be implemented for type SR
  if (dir == (record_i->shuffleID > record_j->shuffleID)) {
    // swap should take place
    std::memset(swap_space, 1, sizeof(trainRecordSerialized));
  } else {
    // No need for swap
    std::memset(swap_space, 0, sizeof(trainRecordSerialized));
  }

  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  uint8_t *p_i = (uint8_t *)(record_i);
  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  uint8_t *p_j = (uint8_t *)(record_j);
  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  uint8_t *p_temp = (uint8_t *)(&temp);

  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  for (int x = 0; x < sizeof(trainRecordSerialized); ++x) {
    p_i[x] = swap_space[x] * p_j[x] + (1 - swap_space[x]) * p_temp[x];
    p_j[x] = (1 - swap_space[x]) * p_j[x] + swap_space[x] * p_temp[x];
  }

  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  // LRUCache_[i] = record_i;
  // LRUCache_[j] = record_j;

  // cache_size = LRUCache_.size();
  // count_size = LRUCounts_.size();

  // int dummy = 0;
  // if (dummy == 1 /* && cache_size != count_size */) {
  // ++dummy;
  // } else {
  // ++dummy;
  // }

  // encrypt and copy to destination
  // enc_tuple_i = cryptoEngine_.encrypt(decrypted_i);
  // enc_tuple_j = cryptoEngine_.encrypt(decrypted_j);

  // auto temp_enc = std::get<0>(enc_tuple_i);
  // std::memcpy(&(enc_r_i->encData), &temp_enc[0],
  // sizeof(trainRecordSerialized));
  // auto temp_IV = std::get<1>(enc_tuple_i);
  // std::memcpy((enc_r_i->IV), &temp_IV[0], 12);
  // auto temp_MAC = std::get<2>(enc_tuple_i);
  // std::memcpy((enc_r_i->MAC), &temp_MAC[0], 16);

  // temp_enc = std::get<0>(enc_tuple_j);
  // std::memcpy(&(enc_r_j->encData), &temp_enc[0],
  // sizeof(trainRecordSerialized));
  // temp_IV = std::get<1>(enc_tuple_j);
  // std::memcpy((enc_r_j->IV), &temp_IV[0], 12);
  // temp_MAC = std::get<2>(enc_tuple_j);
  // std::memcpy((enc_r_j->MAC), &temp_MAC[0], 16);

  // res =
  //     ocall_set_record_sort(i, &enc_payload_i[0],
  //     sizeof(trainRecordEncrypted),
  //                           j, &enc_payload_j[0],
  //                           sizeof(trainRecordEncrypted));
  // if (res != SGX_SUCCESS) {
  //   printf("ocall set record sort caused problem! the error is "
  //             "%#010X \n",
  //             res);
  //   abort();
  // }
}

// template <typename SR>
// int BitonicSorter<SR>::greatestPowerofTwoLesThan(int n) {
int BitonicSorter::greatestPowerofTwoLessThan(int n) {
  int k = 1;
  while (k > 0 && k < n)
    k = k << 1;
  return k >> 1;
}

// inline
void BitonicSorter::prepareRecords(int i, int j) {
  // static uint32_t call_counts = 0;
  // ++call_counts;
  auto iter_i = LRUCache_.find(i);
  // if (iter_i == LRUCache_.end() && iter_j == LRUCache_.end()) {
  // none of them is n

  // } else

  if (iter_i == LRUCache_.end()) {
    std::vector<size_t> not_in_cache_neighbours;
    std::vector<size_t> in_cache_delete;
    handleCache(i, not_in_cache_neighbours, in_cache_delete);
  }

  auto iter_j = LRUCache_.find(j);
  if (iter_j == LRUCache_.end()) {
    std::vector<size_t> not_in_cache_neighbours;
    std::vector<size_t> in_cache_delete;
    handleCache(j, not_in_cache_neighbours, in_cache_delete);
  }
  // else {
  //   // they are both in cache
  // }
}

// inline
void BitonicSorter::addToCache(
    const std::vector<size_t> &not_in_cache_neighbours) {

  // static uint32_t call_counts = 0;
  // ++call_counts;
  const int list_size = not_in_cache_neighbours.size();
  std::vector<uint8_t> enc_payload(sizeof(trainRecordEncrypted));
  std::vector<uint8_t> enc_data(sizeof(trainRecordSerialized));
  std::array<uint8_t, 12> IV;
  std::array<uint8_t, 16> MAC;
  // for (int ind = 0; ind < not_in_cache_neighbours.size(); ++ind) {
  for (int ind = 0; ind < list_size; ++ind) {
    sgx_status_t res = SGX_ERROR_UNEXPECTED;
    res = ocall_get_records_encrypted(1,not_in_cache_neighbours[ind], &enc_payload[0],
                            sizeof(trainRecordEncrypted));
    if (res !=
        SGX_SUCCESS /* || (len_i == len_j && len_i = sizeof(trainRecordEncrypted)) */) {
      printf("ocall get records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }
    trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(enc_payload[0]);
    std::memcpy(&enc_data[0], &(enc_r->encData), sizeof(trainRecordSerialized));
    std::memcpy(&IV[0], (enc_r->IV), AES_GCM_IV_SIZE);
    std::memcpy(&MAC[0], (enc_r->MAC), AES_GCM_TAG_SIZE);

    auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
    // printf("oblivious compared called for %d times\n",++num_calls);
    auto decrypted = cryptoEngine_.decrypt(enc_tuple);
    trainRecordSerialized *record = (trainRecordSerialized *)&(decrypted[0]);
    // LRUCache_[not_in_cache_neighbours[ind]] = *record;
    const auto curr_ind = not_in_cache_neighbours[ind];
    LRUCache_[curr_ind] = *record;

    Time_++;
    LRUCounts_[Time_] = curr_ind;
  }
}

// inline
void BitonicSorter::removeFromCache(
    const std::vector<size_t> &in_cache_delete) {

  // static uint32_t call_counts = 0;
  // ++call_counts;
  std::vector<uint8_t> decrypted(sizeof(trainRecordSerialized));
  std::vector<uint8_t> encrypted(sizeof(trainRecordEncrypted));
  trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(encrypted[0]);

  for (int i = 0; i < in_cache_delete.size(); ++i) {
    // encrypt and store
    sgx_status_t res = SGX_ERROR_UNEXPECTED;
    int array_index = LRUCounts_[in_cache_delete[i]];

    std::memcpy(&decrypted[0], &(LRUCache_[array_index]),
                sizeof(trainRecordSerialized));
    auto enc_tuple = cryptoEngine_.encrypt(decrypted);

    const auto &temp_enc = std::get<0>(enc_tuple);
    std::memcpy(&(enc_r->encData), &temp_enc[0], sizeof(trainRecordSerialized));
    const auto &temp_IV = std::get<1>(enc_tuple);
    std::memcpy((enc_r->IV), &temp_IV[0], AES_GCM_IV_SIZE);
    const auto &temp_MAC = std::get<2>(enc_tuple);
    std::memcpy((enc_r->MAC), &temp_MAC[0], AES_GCM_KEY_SIZE);

    res = ocall_set_records_encrypted(1,array_index, &encrypted[0],
                            sizeof(trainRecordEncrypted));
    if (res != SGX_SUCCESS) {
      printf("ocall set records caused problem! the error is "
                "%#010X \n",
                res);
      abort();
    }
    // remove
    LRUCache_.erase(array_index);
    LRUCounts_.erase(in_cache_delete[i]);
    // lastInd_ = in_cache_delete[i];
  }
}

// inline
void BitonicSorter::handleCache(int i,
                                std::vector<size_t> &not_in_cache_neighbours,
                                std::vector<size_t> &in_cache_delete) {
  // static int num_calls = 0;
  // ++num_calls;
  // auto b_cache_size = LRUCache_.size();
  // auto b_count_size = LRUCounts_.size();
  // not_in_cache_neighbours.clear();
  not_in_cache_neighbours.reserve(CACHE_NEIGHBOR_BRING);
  not_in_cache_neighbours.push_back(i);
  bool dir_add = false;
  for (int ind = 1; ind < CACHE_NEIGHBOR_BRING; ++ind) {
    if (i + ind < arrayLen_) {
      const auto iter = LRUCache_.find(i + ind);
      if (iter == LRUCache_.end()) {
        not_in_cache_neighbours.push_back(i + ind);
      }
    }
  }
  if (LRUCache_.size() + not_in_cache_neighbours.size() <= CACHE_MAX_SIZE) {
    addToCache(not_in_cache_neighbours);
    // dir_add = true;
  } else {
    // Evict first
    // in_cache_delete.clear();
    in_cache_delete.reserve(CACHE_NEIGHBOR_BRING);
    for (auto count_iter = LRUCounts_.begin(); count_iter != LRUCounts_.end();
         count_iter++) {
      if (in_cache_delete.size() ==
          not_in_cache_neighbours.size() -
              (CACHE_MAX_SIZE - LRUCache_.size())) {
        break;
      }
      // if (count_iter->second >= i &&
      //     count_iter->second < i + CACHE_NEIGHBOR_BRING &&
      //     count_iter->second < arrayLen_) {
      if (std::find(not_in_cache_neighbours.begin(),
                    not_in_cache_neighbours.end(),
                    count_iter->second) != std::end(not_in_cache_neighbours)) {
        continue;
      }

      in_cache_delete.push_back(count_iter->first);
    }
    removeFromCache(in_cache_delete);
    addToCache(not_in_cache_neighbours);
  }
  // auto cache_size = LRUCache_.size();
  // auto count_size = LRUCounts_.size();
  // auto add_size = not_in_cache_neighbours.size();
  // auto del_size = in_cache_delete.size();

  // int dummy = 0;
  // if (!dir_add  && cache_size != count_size) {
  // ++dummy;
  // } else {
  // ++dummy;
  // }
}
}
}
