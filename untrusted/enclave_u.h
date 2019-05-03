#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_LOAD_NET_CONFIG_DEFINED__
#define OCALL_LOAD_NET_CONFIG_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_net_config, (const unsigned char* path, size_t path_len, char* config, size_t config_len, unsigned int* real_len, unsigned char* config_iv, unsigned char* config_mac));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_GET_RECORD_SORT_DEFINED__
#define OCALL_GET_RECORD_SORT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_record_sort, (int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j));
#endif
#ifndef OCALL_SET_RECORD_SORT_DEFINED__
#define OCALL_SET_RECORD_SORT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_set_record_sort, (int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j));
#endif
#ifndef OCALL_GET_RECORDS_DEFINED__
#define OCALL_GET_RECORDS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_records, (size_t i, unsigned char* tr_record_i, size_t len_i));
#endif
#ifndef OCALL_SET_RECORDS_DEFINED__
#define OCALL_SET_RECORDS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_set_records, (size_t i, unsigned char* tr_record_i, size_t len_i));
#endif
#ifndef OCALL_SET_TIMING_DEFINED__
#define OCALL_SET_TIMING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_set_timing, (const char* time_id, size_t len, int is_it_first_call, int is_it_last_call));
#endif
#ifndef OCALL_WRITE_BLOCK_DEFINED__
#define OCALL_WRITE_BLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_block, (int64_t block_id, size_t index, unsigned char* buff, size_t len));
#endif
#ifndef OCALL_READ_BLOCK_DEFINED__
#define OCALL_READ_BLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_block, (int64_t block_id, size_t index, unsigned char* buff, size_t len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid);
sgx_status_t ecall_assign_random_id(sgx_enclave_id_t eid, unsigned char* tr_records, size_t len);
sgx_status_t ecall_initial_sort(sgx_enclave_id_t eid);
sgx_status_t ecall_check_for_sort_correctness(sgx_enclave_id_t eid);
sgx_status_t ecall_start_training(sgx_enclave_id_t eid);
sgx_status_t ecall_singal_convolution(sgx_enclave_id_t eid, int size1, int size2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
