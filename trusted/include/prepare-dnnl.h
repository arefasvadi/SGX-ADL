#pragma once
#ifdef USE_SGX
#undef error
#include "common.h"
#include "dnnl.hpp"
#include "example_utils.h"

void simple_dnnl_mult();
void main_logger(int level, const char *file, int line, const char *format,
                 ...);

using namespace dnnl;
extern engine eng;

void blasfeo_gemv_impl(int ta, int m, int n, float alpha, float *A, int lda, float *x, int incx, float beta, float *y, int incy);

template<int BETA>
dnnl::inner_product_forward dynamic_matvec_create_beta() {
    // We assume that beta is known at the primitive creation time
    float beta = BETA;
    memory::dims a_shape = {1,DNNL_RUNTIME_DIM_VAL}; // vector
    memory::dims b_shape = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL}; // matrix
    memory::dims c_shape = {1,DNNL_RUNTIME_DIM_VAL}; // vector result
    memory::dims a_strides = {DNNL_RUNTIME_DIM_VAL,1};
    memory::dims b_strides = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL};
    memory::dims c_strides = {DNNL_RUNTIME_DIM_VAL,1};
    memory::desc a_md(a_shape, memory::data_type::f32, a_strides);
    memory::desc b_md(b_shape, memory::data_type::f32, b_strides);
    memory::desc c_md(c_shape, memory::data_type::f32, c_strides);
    // Create attributes (to handle alpha dynamically and beta if necessary)
    primitive_attr attr;
    attr.set_output_scales(/* mask */ 0, {DNNL_RUNTIME_F32_VAL});
    if (BETA != 0.f) {
        post_ops po;
        po.append_sum(beta);
        attr.set_post_ops(po);
    }
    LOG_DEBUG("creaing desc\n");
    auto inner_product_d
            = inner_product_forward::desc(prop_kind::forward_training, a_md,
                    b_md, c_md);
    LOG_DEBUG("creating desc_pd\n");
    auto inner_product_pd = inner_product_forward::primitive_desc(inner_product_d,attr,eng);
    LOG_DEBUG("retturning desc_pd\n");
    return inner_product_forward(inner_product_pd);
}

void dynamic_matvec_execute(inner_product_forward &inner_product_primitive, char transB,
        int64_t M, int64_t N, float alpha, const float *src,
        const float *weights, int64_t ldb,float *res);

void primitive_based_sgemv(char transA, char transB, 
        int64_t M,int64_t N, int64_t K,
        float alpha,
        float* A,int64_t lda,
        float* B,int64_t ldb,
        float beta,
        float* C,int64_t ldc);

template<int BETA>
matmul dynamic_matmul_create_beta() {
    // We assume that beta is known at the primitive creation time
    float beta = BETA;
    memory::dims a_shape = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL};
    memory::dims b_shape = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL};
    memory::dims c_shape = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL};
    memory::dims a_strides = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL};
    memory::dims b_strides = {DNNL_RUNTIME_DIM_VAL, DNNL_RUNTIME_DIM_VAL};
    memory::dims c_strides = {DNNL_RUNTIME_DIM_VAL, 1};
    memory::desc a_md(a_shape, memory::data_type::f32, a_strides);
    memory::desc b_md(b_shape, memory::data_type::f32, b_strides);
    memory::desc c_md(c_shape, memory::data_type::f32, c_strides);
    // Create attributes (to handle alpha dynamically and beta if necessary)
    primitive_attr attr;
    attr.set_output_scales(/* mask */ 0, {DNNL_RUNTIME_F32_VAL});
    if (BETA != 0.f) {
        post_ops po;
        po.append_sum(beta);
        attr.set_post_ops(po);
    }
    // Create a MatMul primitive
    matmul::desc matmul_d(a_md, b_md, c_md);
    matmul::primitive_desc matmul_pd(matmul_d, attr, eng);
    return matmul(matmul_pd);
}


// matmul dynamic_matmul_create_beta0();
// matmul dynamic_matmul_create_beta1();

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
