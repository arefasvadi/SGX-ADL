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
void ecall_singal_convolution(int size1, int size2);
void ecall_matrix_mult(int row1, int col1, int row2, int col2);

sgx_status_t SGX_CDECL ocall_load_net_config(const unsigned char* path, size_t path_len, char* config, size_t config_len, unsigned int* real_len, unsigned char* config_iv, unsigned char* config_mac);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_log(const char* str);
sgx_status_t SGX_CDECL ocall_get_record_sort(int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j);
sgx_status_t SGX_CDECL ocall_set_record_sort(int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j);
sgx_status_t SGX_CDECL ocall_get_records(size_t i, unsigned char* tr_record_i, size_t len_i);
sgx_status_t SGX_CDECL ocall_set_records(size_t i, unsigned char* tr_record_i, size_t len_i);
sgx_status_t SGX_CDECL ocall_set_timing(const char* time_id, size_t len, int is_it_first_call, int is_it_last_call);
sgx_status_t SGX_CDECL ocall_write_block(int64_t block_id, size_t index, unsigned char* buff, size_t len);
sgx_status_t SGX_CDECL ocall_read_block(int64_t block_id, size_t index, unsigned char* buff, size_t len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
