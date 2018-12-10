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

sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid);
sgx_status_t ecall_assign_random_id(sgx_enclave_id_t eid, unsigned char* tr_records, size_t len);
sgx_status_t ecall_initial_sort(sgx_enclave_id_t eid);
sgx_status_t ecall_check_for_sort_correctness(sgx_enclave_id_t eid);
sgx_status_t ecall_start_training(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
