#pragma once
#include "common-structures.h"
#include "sgx_tcrypto.h"

extern int gpu_index ;
extern CommonRunConfig comm_run_config;
extern int printf(const char *fmt, ...);

extern sgx_aes_gcm_128bit_key_t enclave_ases_gcm_key;
extern sgx_aes_gcm_128bit_key_t client_ases_gcm_key;

extern sgx_ec256_public_t enclave_sig_pk_key;
extern sgx_ec256_private_t enclave_sig_sk_key;
extern sgx_ec256_public_t client_sig_pk_key;

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
} 
#endif
