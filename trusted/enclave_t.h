#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_enclave_init(void);
void ecall_assign_random_id(unsigned char* tr_records, size_t len);
void ecall_initial_sort(void);
void ecall_check_for_sort_correctness(void);
void ecall_start_training(void);

sgx_status_t SGX_CDECL ocall_load_net_config(const unsigned char* path, size_t path_len, char* config, size_t config_len, unsigned int* real_len, unsigned char* config_iv, unsigned char* config_mac);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_get_record_sort(int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j);
sgx_status_t SGX_CDECL ocall_set_record_sort(int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j);
sgx_status_t SGX_CDECL ocall_get_records(size_t i, unsigned char* tr_record_i, size_t len_i);
sgx_status_t SGX_CDECL ocall_set_records(size_t i, unsigned char* tr_record_i, size_t len_i);
sgx_status_t SGX_CDECL ocall_set_timing(const char* time_id, size_t len, int is_it_first_call);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
