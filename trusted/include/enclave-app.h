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
#include "concurrentqueue.h"
#include  <unordered_set>
#include <queue>
//#include "../../third_party/libxsmm/include/libxsmm.h"
//#include "blasfeo_s_blas.h"

//void blasfeo_sgemm(char *ta, char *tb, int *pm, int *pn, int *pk, float *alpha, float *A, int *plda, float *B, int *pldb, float *beta, float *C, int *pldc);

bool float_equal(const float a,const float b);

void
send_batch_seed_to_gpu(const int iteration);

bool
verify_sha256_single_round(const uint8_t* provided_sha256,
                           const uint8_t* buffer,
                           const size_t   buffer_len,
                           const char*    msg) ;

bool
verify_sha256_mult_rounds(sgx_sha_state_handle_t* sha256_handle,
                          const uint8_t* provided_sha256,
                          const uint8_t* buffer,
                          const size_t   buffer_len,
                          const char*    msg);


bool verify_cmac128_single_round(const uint8_t* msg,const size_t msg_len,
    const uint8_t* tag,const uint8_t* aad,const size_t aad_len);
bool
gen_verify_cmac128_multiple_rounds(const bool generate,
                               sgx_cmac_state_handle_t* cmac_handle,
                               uint8_t*                 msg,
                               size_t                   msg_len,
                               uint8_t*                 tag,
                               uint8_t*                 aad,
                               size_t                   aad_len);

void start_training_verification_frbv(int iteration);
void start_training_verification_frbmmv(int iteration);
void start_training_in_sgx(int iteration);

void apply_weight_updates(int iteration,network* net);

void
apply_clipping_then_update(network* netp);

void save_load_params_and_update_snapshot_(bool save,int iteration,network* net);

std::array<uint64_t, 16> generate_random_seed_from(PRNG &rng);
void setup_layers_iteration_seed(network& net, int iteration);

void fix_task_dependent_global_vars();

void init_net();

void init_net_train_integ_layered(const net_init_training_integrity_layered_args* args);
void init_net_train_privacy_integ_layered(const net_init_training_privacy_integrity_layered_args* args);


void verify_init_dataset();
additional_auth_data construct_aad_input_nochange(uint32_t id);
additional_auth_data construct_aad_frbv_report_nochange_ts(uint32_t id,uint32_t ts);
additional_auth_data construct_aad_frbv_comp_subcomp_nots(uint32_t comp_id,uint32_t subcomp_id);
// void encrypt_input_sgx_session_key(uint8_t* enc_buff,const uint8_t* dec_buff,size_t len,
//                                    const additional_auth_data* aad,uint8_t* iv,sgx_aes_gcm_128bit_tag_t* tag);

void verify_task_frbv();
void verify_task_frbmmv();
void setup_iteration_inputs_training(std::queue<int>& queued_ids, std::set<int> &selected_ids_prev, network* net,
                                     int iteration, int size,int low,int high);
void setup_iteration_inputs_training_enc_layered_fit(std::queue<int>& queued_ids, std::set<int> &selected_ids_prev, network* net,
                                     int iteration, int size,int low,int high);

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
void choose_rand_privacy_integrity_set_nonbliv(const integrity_set_func_obliv_indleak_args_* args);

void verify_init_net_config();

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
} 
#endif
