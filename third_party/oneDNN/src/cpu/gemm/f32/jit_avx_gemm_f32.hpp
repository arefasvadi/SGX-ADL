/*******************************************************************************
* Copyright 2016-2020 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef JIT_AVX_GEMM_F32_HPP
#define JIT_AVX_GEMM_F32_HPP

#include "dnnl_types.h"
#include "gemm_utils_f32.hpp"

namespace dnnl {
namespace impl {
namespace cpu {

dnnl_status_t jit_avx_gemm_f32(const char *transa, const char *transb,
        const dim_t *M, const dim_t *N, const dim_t *K, const float *alpha,
        const float *A, const dim_t *lda, const float *B, const dim_t *ldb,
        const float *beta, float *C, const dim_t *ldc,
        const float *bias = nullptr);

namespace avx_gemm_f32 {

void sgemm_nocopy_driver(const char *transa, const char *transb, dim_t m,
        dim_t n, dim_t k, const float *alpha, const float *a, dim_t lda,
        const float *b, dim_t ldb, const float *beta, float *c, dim_t ldc,
        const float *bias, float *ws);
}

} // namespace cpu
} // namespace impl
} // namespace dnnl

#endif // JIT_AVX_GEMM_F32_HPP
