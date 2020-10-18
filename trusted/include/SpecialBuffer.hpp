#pragma once
#include <stdint.h>

#include <memory>
#include <vector>

#include "SpecialBufferCommon.h"
#include "common.h"
#include "enclave_t.h"
//#include "gsl/gsl-lite.hpp"
#include "timingdefs.h"

namespace sgx {
  namespace trusted {
    namespace std = ::std;

    template <typename T>
    class SpecialBuffer : public SpecialBufferCommon {
      public:
      explicit SpecialBuffer(const uint32_t size);
      virtual ~SpecialBuffer() = default;
      std::unique_ptr<T[]>
      getItemsInRange(const uint32_t start, const uint32_t end);

      // gsl::span<T>
      // getItemsInRangeSpan(const uint32_t start, const uint32_t end);

      void
      setItemsInRange(const uint32_t        start,
                      const uint32_t        end,
                      std::unique_ptr<T[]> &content);
      // void
      // setItemsInRangeSpan(const uint32_t start,
      //                 const uint32_t end,
      //                 gsl::span<T> & content);

      inline uint32_t
      getBufferSize() {
        return buffSize_;
      };
      inline uint32_t
      getID() {
        return id_;
      };
      static std::shared_ptr<SpecialBuffer<T>>
      GetNewSpecialBuffer(const uint32_t size);

      private:
      void
                     initiateBufferOutside();
      const uint32_t buffSize_;
      const uint32_t id_;
    };

    template <typename T>
    SpecialBuffer<T>::SpecialBuffer(const uint32_t size) :
        SpecialBufferCommon(), buffSize_(size),
        id_(++SpecialBufferCommon::currID_) {
      SpecialBufferCommon::overallBytesConsumed_ += buffSize_ * sizeof(T);
      initiateBufferOutside();
    }

    template <typename T>

    std::shared_ptr<SpecialBuffer<T>>
    SpecialBuffer<T>::GetNewSpecialBuffer(const uint32_t size) {
      return std::make_shared<SpecialBuffer<T>>(size);
    }

    template <typename T>
    void
    SpecialBuffer<T>::initiateBufferOutside() {
      sgx_status_t succ = SGX_ERROR_UNEXPECTED;
      succ = ocall_init_buffer_layerwise(id_, buffSize_ * sizeof(T));
      CHECK_SGX_SUCCESS(succ, "Problem Caused by INIT Buffer LayerWise");
    }

    template <typename T>
    std::unique_ptr<T[]>
    SpecialBuffer<T>::getItemsInRange(const uint32_t start,
                                      const uint32_t end) {
      SET_START_TIMING("SpecialBuffer Get Item")
      assert(end > start);
      sgx_status_t succ             = SGX_ERROR_UNEXPECTED;
      const size_t buff_len         = end - start;
      const size_t interim_buff_len = SGX_OCALL_TRANSFER_BLOCK_SIZE / sizeof(T);
      SET_START_TIMING("SpecialBuffer Get Item Allocation")
      auto         ret              = std::unique_ptr<T[]>(new T[buff_len]);
      SET_FINISH_TIMING("SpecialBuffer Get Item Allocation")
      
      int q = buff_len / (interim_buff_len);
      int r = buff_len % (interim_buff_len);
      
      #pragma omp parallel for
      for (int i = 0; i < q; ++i) {
        succ = ocall_get_buffer_layerwise(
            id_,
            (start + i * interim_buff_len) * sizeof(T),
            (start + (i + 1) * interim_buff_len) * sizeof(T),
            (unsigned char *)(&ret[i * interim_buff_len]),
            (interim_buff_len) * sizeof(T));
        CHECK_SGX_SUCCESS(succ, "Problem Caused by Get Buffer LayerWise");
      }
      if (r != 0) {
        succ = ocall_get_buffer_layerwise(
            id_,
            (start + q * interim_buff_len) * sizeof(T),
            (start + q * interim_buff_len + r) * sizeof(T),
            (unsigned char *)(&ret[q * interim_buff_len]),
            (r) * sizeof(T));
        CHECK_SGX_SUCCESS(succ, "Problem Caused by Get Buffer LayerWise");
      }
      SET_FINISH_TIMING("SpecialBuffer Get Item")
      return ret;
    }

    template <typename T>
    void
    SpecialBuffer<T>::setItemsInRange(const uint32_t        start,
                                      const uint32_t        end,
                                      std::unique_ptr<T[]> &content) {
      SET_START_TIMING("SpecialBuffer Set Item")
      assert(end > start);
      const size_t buff_len         = end - start;
      const size_t interim_buff_len = SGX_OCALL_TRANSFER_BLOCK_SIZE / sizeof(T);
      sgx_status_t succ             = SGX_ERROR_UNEXPECTED;
      int          q                = buff_len / (interim_buff_len);
      int          r                = buff_len % (interim_buff_len);
      
      #pragma omp parallel for
      for (int i = 0; i < q; ++i) {
        succ = ocall_set_buffer_layerwise(
            id_,
            (start + i * interim_buff_len) * sizeof(T),
            (start + (i + 1) * interim_buff_len) * sizeof(T),
            (unsigned char *)&(content[i * interim_buff_len]),
            interim_buff_len * sizeof(T));
        CHECK_SGX_SUCCESS(succ, "Problem Caused by Set Buffer LayerWise");
      }
      if (r != 0) {
        succ = ocall_set_buffer_layerwise(
            id_,
            (start + q * interim_buff_len) * sizeof(T),
            (start + q * interim_buff_len + r) * sizeof(T),
            (unsigned char *)&(content[q * interim_buff_len]),
            (r) * sizeof(T));
        CHECK_SGX_SUCCESS(succ, "Problem Caused by Set Buffer LayerWise");
      }
      SET_FINISH_TIMING("SpecialBuffer Set Item")
    }

    //template class SpecialBuffer<float>;
    //template class SpecialBuffer<int>;
    //template class SpecialBuffer<char>;

  }  // namespace trusted
}  // namespace sgx