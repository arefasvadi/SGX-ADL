#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_load_net_config_t {
	unsigned char* ms_path;
	size_t ms_path_len;
	char* ms_config;
	size_t ms_config_len;
} ms_ocall_load_net_config_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_ocall_load_net_config(void* pms)
{
	ms_ocall_load_net_config_t* ms = SGX_CAST(ms_ocall_load_net_config_t*, pms);
	ocall_load_net_config((const unsigned char*)ms->ms_path, ms->ms_path_len, ms->ms_config, ms->ms_config_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_enclave = {
	2,
	{
		(void*)enclave_ocall_load_net_config,
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, NULL);
	return status;
}

