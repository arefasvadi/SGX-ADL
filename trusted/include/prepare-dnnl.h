#pragma once
#undef error
#include "dnnl.hpp"
void simple_dnnl_mult();

#if 1
using namespace dnnl;
matmul dynamic_matmul_create_beta0();
matmul dynamic_matmul_create_beta1();

void dynamic_matmul_execute(matmul &matmul_p, char transA, char transB,
        int64_t M, int64_t N, int64_t K, float alpha, const float *A,
        int64_t lda, const float *B, int64_t ldb, float beta, float *C,
        int64_t ldc);

void primitive_based_sgemm(char transA, char transB, 
        int64_t M,int64_t N, int64_t K,
        float alpha,
        float* A,int64_t lda,
        float* B,int64_t ldb,
        float beta,
        float* C,int64_t ldc);
#endif