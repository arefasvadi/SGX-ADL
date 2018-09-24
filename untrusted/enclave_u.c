#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_load_net_config_t {
	const unsigned char* ms_path;
	size_t ms_path_len;
	char* ms_config;
	size_t ms_config_len;
	unsigned int* ms_real_len;
	unsigned char* ms_config_iv;
	unsigned char* ms_config_mac;
} ms_ocall_load_net_config_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_ocall_load_net_config(void* pms)
{
	ms_ocall_load_net_config_t* ms = SGX_CAST(ms_ocall_load_net_config_t*, pms);
	ocall_load_net_config(ms->ms_path, ms->ms_path_len, ms->ms_config, ms->ms_config_len, ms->ms_real_len, ms->ms_config_iv, ms->ms_config_mac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

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

