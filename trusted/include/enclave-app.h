#pragma once
#include "common-structures.h"
#include "sgx_tcrypto.h"
#include "flatbuffers/flatbuffers.h"
#include "fbs_gen_code/taskconfig_generated.h"
#include "fbs_gen_code/signedECC_generated.h"
#include "flats-util.hpp"
#include "memory-SGX-missing.h"
#include "rand/PRNG.h"
#include <deque>
#include "Enclave-Types.h"
#include "global-vars-trusted.h"
#include "rand/PRNGHelper.h"
//#include "../../third_party/libxsmm/include/libxsmm.h"
//#include "blasfeo_s_blas.h"

//void blasfeo_sgemm(char *ta, char *tb, int *pm, int *pn, int *pk, float *alpha, float *A, int *plda, float *B, int *pldb, float *beta, float *C, int *pldc);


void
send_batch_seed_to_gpu(const int iteration);

bool
verify_sha256_single_round(const uint8_t* provided_sha256,
                           const uint8_t* buffer,
                           const size_t   buffer_len,
                           const char*    msg) ;

void fix_task_dependent_global_vars();

void init_net();

void init_net_train_integ_layered(const net_init_training_integrity_layered_args*);

void verify_init_dataset();
additional_auth_data construct_aad_input_nochange(uint32_t id);

// void encrypt_input_sgx_session_key(uint8_t* enc_buff,const uint8_t* dec_buff,size_t len,
//                                    const additional_auth_data* aad,uint8_t* iv,sgx_aes_gcm_128bit_tag_t* tag);

std::vector<uint8_t>
generate_image_label_flatb_from_actual_bytes(const std::vector<uint8_t> in_vec);

std::vector<uint8_t>
generate_auth_flatbuff(const std::vector<uint8_t>& in_vec,
                       const additional_auth_data* aad,
                       sgx_cmac_state_handle_t* cmac_handle);

std::vector<uint8_t>
generate_enc_auth_flatbuff(const std::vector<uint8_t>& in_vec,
                       const additional_auth_data* aad);

void choose_rand_integrity_set_nonbliv(const integrity_set_func_obliv_indleak_args_* args);

void
verify_init_net_config();

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
} 
#endif
