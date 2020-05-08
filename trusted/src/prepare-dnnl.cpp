#include "prepare-dnnl.h"
#include "enclave_t.h"
#if 1
using namespace dnnl;


engine eng(engine::kind::cpu, 0); // We create a global engine for simplicity

// Create a _dynamic_ MatMul primitive that can work with arbitrary shapes
// and alpha parameters.
// Warning: current limitation is that beta parameter should be known in
// advance (use fixed_beta).
matmul dynamic_matmul_create_beta0() {
    // We assume that beta is known at the primitive creation time
    float beta = 0;
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
    if (beta != 0.f) {
        post_ops po;
        po.append_sum(beta);
        attr.set_post_ops(po);
    }
    // Create a MatMul primitive
    matmul::desc matmul_d(a_md, b_md, c_md);
    matmul::primitive_desc matmul_pd(matmul_d, attr, eng);
    return matmul(matmul_pd);
}

matmul dynamic_matmul_create_beta1() {
    // We assume that beta is known at the primitive creation time
    float beta = 1.0;
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
    if (beta != 0.f) {
        post_ops po;
        po.append_sum(beta);
        attr.set_post_ops(po);
    }
    // Create a MatMul primitive
    matmul::desc matmul_d(a_md, b_md, c_md);
    matmul::primitive_desc matmul_pd(matmul_d, attr, eng);
    return matmul(matmul_pd);
}

// Execute a _dynamic_ MatMul primitive created earlier. All the parameters are
// passed at a run-time (except for beta which has to be specified at the
// primitive creation time due to the current limitation).
void dynamic_matmul_execute(matmul &matmul_p, char transA, char transB,
        int64_t M, int64_t N, int64_t K, float alpha, const float *A,
        int64_t lda, const float *B, int64_t ldb, float beta, float *C,
        int64_t ldc) {
    using dims = memory::dims;
    if (beta !=0.0 && beta !=1.0f) {
        ocall_print_log("Run-time beta is not yet supported.");
        throw std::logic_error("Run-time beta is not yet supported.");
    }        
    // Translate transA and transB
    dims a_strides = tolower(transA) == 'n' ? dims {lda, 1} : dims {1, lda};
    dims b_strides = tolower(transB) == 'n' ? dims {ldb, 1} : dims {1, ldb};
    // Wrap raw pointers into oneDNN memories (with proper shapes)
    memory A_m({{M, K}, memory::data_type::f32, a_strides}, eng, (void *)A);
    memory B_m({{K, N}, memory::data_type::f32, b_strides}, eng, (void *)B);
    memory C_m({{M, N}, memory::data_type::f32, {ldc, 1}}, eng, (void *)C);
    // Prepare oneDNN memory for alpha
    memory alpha_m({{1}, memory::data_type::f32, {1}}, eng, &alpha);
    // Execute the MatMul primitive
    stream s(eng);
    matmul_p.execute(s,
            {{DNNL_ARG_SRC, A_m}, {DNNL_ARG_WEIGHTS, B_m}, {DNNL_ARG_DST, C_m},
                    {DNNL_ARG_ATTR_OUTPUT_SCALES, alpha_m}});
    s.wait();
}


void primitive_based_sgemm(char transA, char transB, 
        int64_t M,int64_t N, int64_t K,
        float alpha,
        float* A,int64_t lda,
        float* B,int64_t ldb,
        float beta,
        float* C,int64_t ldc) {
    if (beta !=0.0 && beta !=1.0f) {
        ocall_print_log("Run-time beta is not yet supported.");
        throw std::logic_error("Run-time beta is not yet supported.");
    }  
    matmul dynamic_matmul;
    if (beta == 0.0f) {
        dynamic_matmul = dynamic_matmul_create_beta0();
    }
    else if (beta == 1.0f) {
        dynamic_matmul = dynamic_matmul_create_beta1();
    }
    
    dynamic_matmul_execute(dynamic_matmul, transA, transB, M, N, K, alpha,
                A, lda, B, ldb, beta,C,ldc);
}
#endif