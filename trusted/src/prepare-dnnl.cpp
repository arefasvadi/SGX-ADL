#include "prepare-dnnl.h"
#include "enclave_t.h"
#include "sgx_blasfeo/blasfeo_s_blasfeo_api.h"
#ifdef USE_SGX
#include "common.h"
#include "util.h"
#endif

#if 1
using namespace dnnl;
engine eng(engine::kind::cpu, 0); // We create a global engine for simplicity

void blasfeo_gemv_impl(int ta, int m, int n, float alpha, float *A, int lda, float *x, int incx, float beta, float *y, int incy) {
    char ta_c = (ta == 0) ? 'n':'t';
    if (!ta) {
        //blasfeo_sgemv_n( &m, &n, &alpha, A, &lda, x, &incx, &beta, y, &incy);
    }
    else {
        //blasfeo_sgemv_t( &m, &n, &alpha, A, &lda, x, &incx, &beta, y, &incy);
    }    
}


void dynamic_matvec_execute(inner_product_forward &inner_product_primitive, char transB,
        int64_t M, int64_t N, float alpha, const float *src,
        const float *weights, int64_t ldb,float *res) {
    using dims = memory::dims;
    // if (beta !=0.0 && beta !=1.0f) {
    //     ocall_print_log("Run-time beta is not yet supported.");
    //     throw std::logic_error("Run-time beta is not yet supported.");
    // }        
    dims b_strides = tolower(transB) == 'n' ? dims {ldb, 1} : dims {1, ldb};
    // Wrap raw pointers into oneDNN memories (with proper shapes)
    memory A_v({{M,1}, memory::data_type::f32, {1}}, eng, (void *)src);
    memory B_m({{M, N}, memory::data_type::f32, b_strides}, eng, (void *)weights);
    memory C_v({{N,1}, memory::data_type::f32, {1}}, eng, (void *)res);
    // Prepare oneDNN memory for alpha
    memory alpha_m({{1}, memory::data_type::f32, {1}}, eng, &alpha);
    // Execute the MatMul primitive
    stream s(eng);
    inner_product_primitive.execute(s,
            {{DNNL_ARG_SRC, A_v}, {DNNL_ARG_WEIGHTS, B_m}, {DNNL_ARG_DST, C_v},
                    {DNNL_ARG_ATTR_OUTPUT_SCALES, alpha_m}});
    s.wait();

}

void primitive_based_sgemv(char transA, char transB, 
        int64_t M,int64_t N, int64_t K,
        float alpha,
        float* A,int64_t lda,
        float* B,int64_t ldb,
        float beta,
        float* C,int64_t ldc) {
    
    LOG_WARN("func begin gemv %c%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transA,transB,M,N,K,alpha,beta);
    if (beta !=0.0 && beta !=1.0f) {
        LOG_ERROR("Run-time beta is not yet supported.");
        abort();
    }  
    inner_product_forward inner_prod_primitive;
    if (beta == 0.0f) {
        inner_prod_primitive = dynamic_matvec_create_beta<0>();
    }
    else if (beta == 1.0f) {
        inner_prod_primitive = dynamic_matvec_create_beta<1>();
    }
    
    LOG_WARN("started gemv %c%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transA,transB,M,N,K,alpha,beta);
    // C(M,N)=A(M,K)*B(K,N)
    if (tolower(transA)=='n' && tolower(transB) == 'n'){
        // vec is left c(1,N) = A(1,K) * B(K,N)
        // dnnl -> src=A,weights=B,Res=C
        if (M==1) {
            
            dynamic_matvec_execute(inner_prod_primitive, 'n', K, N, alpha,
                A, B, N, C);
        }
        // vec is right c(M,1) = A(M,K) * B(K,1)
        else if (N==1) {
            dynamic_matvec_execute(inner_prod_primitive, 'n', M, K, alpha,
                B, A, K, C);
        }
        else {
            ocall_print_log("Run-time matvec nn wrong dim");
            throw std::logic_error("Run-time beta is not yet supported.");
        }
    }
    // C(M,N)=A(M,K)*(B(N,K))^
    else if (tolower(transA)=='n' && tolower(transB) == 't'){
        // C(1,N)=A(1,K)*(B(N,K))^
        if (M==1) {
            dynamic_matvec_execute(inner_prod_primitive, 't', N, K, alpha,
                A, B, K, C);
        }
        // C(M,1)=A(M,K)*(B(1,K))^
        else if (N==1) {
            dynamic_matvec_execute(inner_prod_primitive, 'n', M, K, alpha,
                B, A, K, C);
        }
        else {
            ocall_print_log("Run-time matvec nt wrong dim");
            throw std::logic_error("Run-time beta is not yet supported.");
        }
    }
    //dynamic_matvec_execute(inner_prod_primitive, transB, M, N, alpha,
    //            A, B, ldb, C);
    // C(M,N)=A(K,M)^*B(K,N)
    else if (tolower(transA)=='t' && tolower(transB) == 'n'){
        //C(1,N)=A(K,1)^*B(K,N)
        if (M==1) {
            dynamic_matvec_execute(inner_prod_primitive, 'n', K, N, alpha,
                A, B, N, C);
        }
        //C(M,1)=A(K,M)^*B(K,1)
        else if (N==1) {
            dynamic_matvec_execute(inner_prod_primitive, 't', K, M, alpha,
                B, A, M, C);
        }
        else {
            ocall_print_log("Run-time matvec tn wrong dim");
            throw std::logic_error("Run-time beta is not yet supported.");
        }
    }
    else {
        ocall_print_log("Run-time matvec tt is not yet supported.");
        throw std::logic_error("Run-time beta is not yet supported.");
    }
    LOG_WARN("finished gemv %c%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transA,transB,M,N,K,alpha,beta);
}

// Create a _dynamic_ MatMul primitive that can work with arbitrary shapes
// and alpha parameters.
// Warning: current limitation is that beta parameter should be known in
// advance (use fixed_beta).

// Execute a _dynamic_ MatMul primitive created earlier. All the parameters are
// passed at a run-time (except for beta which has to be specified at the
// primitive creation time due to the current limitation).
void dynamic_matmul_execute(matmul &matmul_p, char transA, char transB,
        int64_t M, int64_t N, int64_t K, float alpha, const float *A,
        int64_t lda, const float *B, int64_t ldb, float beta, float *C,
        int64_t ldc) {
    using dims = memory::dims;
    // if (beta !=0.0 && beta !=1.0f) {
    //     ocall_print_log("Run-time beta is not yet supported.");
    //     throw std::logic_error("Run-time beta is not yet supported.");
    // }        
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
    if (/*M==1 || N==1*/ false) {
        primitive_based_sgemv(transA, transB, 
        M,N, K,
        alpha,
        A,lda,
        B,ldb,
        beta,
        C,ldc);
    }
    else {
        if (beta !=0.0 && beta !=1.0f) {
        ocall_print_log("Run-time beta is not yet supported.");
            throw std::logic_error("Run-time beta is not yet supported.");
        }  
        matmul dynamic_matmul;
        if (beta == 0.0f) {
            dynamic_matmul = dynamic_matmul_create_beta<0>();
        }
        else if (beta == 1.0f) {
            dynamic_matmul = dynamic_matmul_create_beta<1>();
        }
        
        dynamic_matmul_execute(dynamic_matmul, transA, transB, M, N, K, alpha,
                    A, lda, B, ldb, beta,C,ldc);
    }
}
#endif