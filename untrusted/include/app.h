#pragma once

#include <assert.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/minireflect.h>
#include <flatbuffers/reflection.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <deque>
#include <string>
#include <vector>
#include "sgx_defs.h"
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */
#include "sgx_uae_service.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"
#include "common-structures.h"
#include "global-vars-untrusted.h"
#include "enclave_u.h"
#include "fbs_gen_code/taskconfig_generated.h"
#include "fbs_gen_code/aes128gcm_generated.h"
#include "fbs_gen_code/cmac128_generated.h"
#include "fbs_gen_code/plainimagelabel_generated.h"
#include "flats-util.hpp"
#include "load-image.h"
#include "rand/PRNG.h"

#ifdef GPU

void check_error(cudaError_t status);
cublasHandle_t blas_handle();
int *cuda_make_int_array(int *x, size_t n);
void cuda_random(float *x_gpu, size_t n);
float cuda_compare(float *x_gpu, float *x, size_t n, char *s);
dim3 cuda_gridsize(size_t n);
void pull_network_output(network *net);
void calc_network_cost(network *net);
#ifdef CUDNN
cudnnHandle_t cudnn_handle();
#endif

#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__GNUC__)
#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "sgxdnn.enclave.signed.so"
#endif

char *get_layer_string(LAYER_TYPE a);

RunConfig
process_json_config(const std::string& f_path);

int
initialize_enclave();

sgx_status_t
dest_enclave(const sgx_enclave_id_t enclave_id);

void
print_timers();

void gen_sha256(const uint8_t* msg, const size_t msg_len, uint8_t* out);

// void
// parse_location_configs(const std::string& location_conf_file,
//                        const std::string& tasktype);
void
prepare_enclave(const std::string& location_conf_file,
                const std::string& tasktype,
                const std::string& verftype);

void prepare_gpu();
void prepare_train_snapshot_frbv(int iter_num);
void prepare_train_snapshot_frbmmv(int iter_num);
void
set_timing(const char *time_id,
                 size_t      len,
                 int         is_it_first_call,
                 int         is_it_last_call);

void start_task();

std::array<uint64_t, 16> generate_random_seed_from(PRNG &rng);
void setup_layers_iteration_seed(network& net, int iteration);

void
main_logger(int level, const char* file, int line, const char* format, ...);

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif
