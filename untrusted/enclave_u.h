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

sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
