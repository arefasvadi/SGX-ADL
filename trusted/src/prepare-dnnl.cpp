#include "prepare-dnnl.h"
#include "enclave_t.h"
#ifdef USE_SGX
#include "common.h"
#include "util.h"
#include "timingdefs.h"
#endif

#if 1
using namespace dnnl;
engine eng(engine::kind::cpu, 0); // We create a global engine for simplicity
void primitive_based_sgemv(char transA, char transB, 
        int64_t M,int64_t N, int64_t K,
        float alpha,
        float* A,int64_t lda,
        float* B,int64_t ldb,
        float beta,
        float* C,int64_t ldc) {
    LOG_ERROR("this primitive is incomplete\naborting..");
    abort();
    if (beta !=0.0 && beta !=1.0f) {
        LOG_ERROR("Run-time beta is not yet supported.");
        abort();
    }  
    inner_product_forward inner_prod_primitive ;
    transA= (transA == 0)?'n':'t';
    transB= (transB == 0)?'n':'t';
    
    LOG_WARN("started gemv %c%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transA,transB,M,N,K,alpha,beta);
    // C(M,N)=A(M,K)*B(K,N)
    char transB_final = 'n';
    if (tolower(transA)=='n' && tolower(transB) == 'n'){
        // vec is left c(1,N) = A(1,K) * B(K,N)
        // dnnl -> src=A,weights=B,Res=C
        if (M==1) {
            transB_final = 'n';
            M=K;
            ldb=N;
        }
        // vec is right c(M,1) = A(M,K) * B(K,1)
        else if (N==1) {
            transB_final = 't';
            N=K;
            ldb=K;
            std::swap(A,B);
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
            transB_final = 't';
            ldb=K;
            M=K;
        }
        // C(M,1)=A(M,K)*(B(1,K))^
        else if (N==1) {
            transB_final = 't';
            ldb=K;
            M=K;
            N=M;
            std::swap(A,B);
        }
        else {
            ocall_print_log("Run-time matvec nt wrong dim");
            throw std::logic_error("Run-time beta is not yet supported.");
        }
    }
    // C(M,N)=A(K,M)^*B(K,N)
    else if (tolower(transA)=='t' && tolower(transB) == 'n'){
        //C(1,N)=A(K,1)^*B(K,N)
        if (M==1) {
            transB_final = 'n';
            M=K;
            ldb=N;
        }
        //C(M,1)=A(K,M)^*B(K,1)
        else if (N==1) {
            transB_final = 'n';
            ldb=M;
            M=K;
            N=M;
            std::swap(A, B);
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

    try{
        LOG_WARN("try_catch gemv transB=%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transB,M,N,K,alpha,beta);
        memory::dims a_shape = {1,M}; // vector
        memory::dims b_shape = {M, N}; // matrix
        memory::dims c_shape = {1,N}; // vector result
        //memory::dims a_strides = {M,1};
        //memory::dims b_strides = {M, N};
        //memory::dims c_strides = {N,1};
        memory::desc a_md(a_shape, memory::data_type::f32, dnnl::memory::format_tag::nc);
        memory::desc a_md_p(a_shape, memory::data_type::f32, dnnl::memory::format_tag::any);
        memory::desc b_md,b_md_p;
        b_md_p = memory::desc(b_shape, memory::data_type::f32, dnnl::memory::format_tag::any);
        if(tolower(transB_final)=='t') {
            b_md = memory::desc(b_shape, memory::data_type::f32, dnnl::memory::format_tag::io);
        }
        else {
            b_md = memory::desc(b_shape, memory::data_type::f32, dnnl::memory::format_tag::oi);
        }
        memory::desc c_md(c_shape, memory::data_type::f32, dnnl::memory::format_tag::nc);
        memory::desc c_md_p(c_shape, memory::data_type::f32, dnnl::memory::format_tag::any);
                
        auto A_v = memory (a_md, eng);
        auto B_m = memory (b_md, eng);
        auto C_v = memory (c_md, eng);
        write_to_dnnl_memory((void*)A, A_v);
        write_to_dnnl_memory((void*)B, B_m);
        write_to_dnnl_memory((void*)C, C_v);
        // Create attributes (to handle alpha dynamically and beta if necessary)
        //primitive_attr attr;
        //attr.set_output_scales(/* mask */ 0, {DNNL_RUNTIME_F32_VAL});
        //if (beta != 0.0f) {
        //    post_ops po;
        //    po.append_sum(beta);
        //    attr.set_post_ops(po);
        //}
        LOG_WARN("try_catch_2 gemv transB=%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transB,M,N,K,alpha,beta);
        auto inner_product_d
                = inner_product_forward::desc(prop_kind::forward_training, a_md_p,b_md_p,c_md_p);
        //auto inner_product_pd = inner_product_forward::primitive_desc(inner_product_d,attr,eng);
        LOG_WARN("try_catch_3 gemv transB=%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transB,M,N,K,alpha,beta);
        auto inner_product_pd = inner_product_forward::primitive_desc(inner_product_d,eng);
        LOG_WARN("try_catc_4 gemv transB=%c M=%d, N=%d, K=%d, alpha=%f, beta=%f\n",transB,M,N,K,alpha,beta);
        auto inner_product_primitive =  inner_product_forward(inner_product_pd);

        LOG_WARN("starting dynamic_matvec_execute\n");
        //using dims = memory::dims;  
        //b_strides = tolower(transB) == 'n' ? dims {ldb, 1} : dims {1, ldb};
        // Wrap raw pointers into oneDNN memories (with proper shapes)
        
        // Prepare oneDNN memory for alpha
        //memory alpha_m({{1}, memory::data_type::f32, {1}}, eng, &alpha);
        // Execute the MatMul primitive
        stream s(eng);
        inner_product_primitive.execute(s,
                {{DNNL_ARG_SRC, A_v}, {DNNL_ARG_WEIGHTS, B_m}, {DNNL_ARG_DST, C_v}}
                );
        s.wait();


    } catch (std::exception &e) {
            LOG_ERROR("caught exception with message %s\n",e.what());
            abort();
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

    if (beta !=0.0 && beta !=1.0f) {
        LOG_ERROR("Run-time beta is not yet supported.");
        abort();
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
#endif