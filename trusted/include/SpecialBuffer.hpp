#pragma once
#include "common.h"
#include "enclave_t.h"
#include <memory>
#include <stdint.h>
#include <vector>
#include "SpecialBufferCommon.h"

namespace sgx {
namespace trusted {
namespace std = ::std;

template <typename T> class SpecialBuffer:public  SpecialBufferCommon{
public:
  explicit SpecialBuffer(const uint32_t size);
  std::vector<T> getItemsInRange(const uint32_t start, const uint32_t end);
  void setItemsInRange(const uint32_t start, const uint32_t end,
                       std::vector<T> &content);
  inline uint32_t getBufferSize() { return buffSize_; };
  inline uint32_t getID() { return id_; };
  static std::shared_ptr<SpecialBuffer<T>>
  GetNewSpecialBuffer(const uint32_t size);

private:
  void initiateBufferOutside();
  const uint32_t buffSize_;
  const uint32_t id_;
};

template <typename T>
SpecialBuffer<T>::SpecialBuffer(const uint32_t size)
    : SpecialBufferCommon(), buffSize_(size), id_(++SpecialBufferCommon::currID_) {
  SpecialBufferCommon::overallBytesConsumed_ += buffSize_ * sizeof(T);
  initiateBufferOutside();
}

template <typename T>

std::shared_ptr<SpecialBuffer<T>>
SpecialBuffer<T>::GetNewSpecialBuffer(const uint32_t size) {
  return std::make_shared<SpecialBuffer<T>>(size);
}

template <typename T> void SpecialBuffer<T>::initiateBufferOutside() {
  sgx_status_t succ = SGX_ERROR_UNEXPECTED;
  succ = ocall_init_buffer_layerwise(id_, buffSize_ * sizeof(T));
  CHECK_SGX_SUCCESS(succ, "Problem Caused by INIT Buffer LayerWise");
}

template <typename T>
std::vector<T> SpecialBuffer<T>::getItemsInRange(const uint32_t start,
                                                 const uint32_t end) {
  assert(end > start);
  sgx_status_t succ = SGX_ERROR_UNEXPECTED;
  const size_t buff_len = end - start;
  const size_t interim_buff_len = 100 * ONE_KB / sizeof(T);
  std::vector<T> ret(buff_len, 0);
  int q = buff_len / (interim_buff_len);
  int r = buff_len % (interim_buff_len);
  for (int i = 0; i < q; ++i) {
    succ = ocall_get_buffer_layerwise(
        id_, (start + i * interim_buff_len) * sizeof(T),
        (start + (i + 1) * interim_buff_len) * sizeof(T),
        (unsigned char *)(&ret[i * interim_buff_len]),
        (interim_buff_len) * sizeof(T));
    CHECK_SGX_SUCCESS(succ, "Problem Caused by Get Buffer LayerWise");
  }
  if (r != 0) {
    succ = ocall_get_buffer_layerwise(
        id_, (start + q * interim_buff_len) * sizeof(T),
        (start + q * interim_buff_len + r) * sizeof(T),
        (unsigned char *)(&ret[q * interim_buff_len]), (r) * sizeof(T));
    CHECK_SGX_SUCCESS(succ, "Problem Caused by Get Buffer LayerWise");
  }

  return ret;
}

template <typename T>
void SpecialBuffer<T>::setItemsInRange(const uint32_t start, const uint32_t end,
                                       std::vector<T> &content) {
  assert(end > start);
  const size_t buff_len = end - start;
  const size_t interim_buff_len = 100 * ONE_KB / sizeof(T);
  sgx_status_t succ = SGX_ERROR_UNEXPECTED;
  int q = buff_len / (interim_buff_len);
  int r = buff_len % (interim_buff_len);
  for (int i = 0; i < q; ++i) {
    succ = ocall_set_buffer_layerwise(
        id_, (start + i * interim_buff_len) * sizeof(T),
        (start + (i + 1) * interim_buff_len) * sizeof(T),
        (unsigned char *)&(content[i * interim_buff_len]),
        interim_buff_len * sizeof(T));
    CHECK_SGX_SUCCESS(succ, "Problem Caused by Set Buffer LayerWise");
  }
  if (r != 0) {
    succ = ocall_set_buffer_layerwise(
        id_, (start + q * interim_buff_len) * sizeof(T),
        (start + q * interim_buff_len + r) * sizeof(T),
        (unsigned char *)&(content[q * interim_buff_len]), (r) * sizeof(T));
    CHECK_SGX_SUCCESS(succ, "Problem Caused by Set Buffer LayerWise");
  }
  //std::memset(&content[0], 0, content.size()*sizeof(T));
}

template class SpecialBuffer<float>;
template class SpecialBuffer<int>;
template class SpecialBuffer<char>;

} // namespace trusted
} // namespace sgx