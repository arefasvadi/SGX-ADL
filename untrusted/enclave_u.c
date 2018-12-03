#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_assign_random_id_t {
	unsigned char* ms_tr_records;
	size_t ms_len;
} ms_ecall_assign_random_id_t;

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

typedef struct ms_ocall_get_record_sort_t {
	int ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
	int ms_j;
	unsigned char* ms_tr_record_j;
	size_t ms_len_j;
} ms_ocall_get_record_sort_t;

typedef struct ms_ocall_set_record_sort_t {
	int ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
	int ms_j;
	unsigned char* ms_tr_record_j;
	size_t ms_len_j;
} ms_ocall_set_record_sort_t;

typedef struct ms_ocall_get_records_t {
	size_t ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
} ms_ocall_get_records_t;

typedef struct ms_ocall_set_records_t {
	size_t ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
} ms_ocall_set_records_t;

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

static sgx_status_t SGX_CDECL enclave_ocall_get_record_sort(void* pms)
{
	ms_ocall_get_record_sort_t* ms = SGX_CAST(ms_ocall_get_record_sort_t*, pms);
	ocall_get_record_sort(ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i, ms->ms_j, ms->ms_tr_record_j, ms->ms_len_j);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_set_record_sort(void* pms)
{
	ms_ocall_set_record_sort_t* ms = SGX_CAST(ms_ocall_set_record_sort_t*, pms);
	ocall_set_record_sort(ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i, ms->ms_j, ms->ms_tr_record_j, ms->ms_len_j);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_get_records(void* pms)
{
	ms_ocall_get_records_t* ms = SGX_CAST(ms_ocall_get_records_t*, pms);
	ocall_get_records(ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_set_records(void* pms)
{
	ms_ocall_set_records_t* ms = SGX_CAST(ms_ocall_set_records_t*, pms);
	ocall_set_records(ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_enclave = {
	6,
	{
		(void*)enclave_ocall_load_net_config,
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_get_record_sort,
		(void*)enclave_ocall_set_record_sort,
		(void*)enclave_ocall_get_records,
		(void*)enclave_ocall_set_records,
	}
};
sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_assign_random_id(sgx_enclave_id_t eid, unsigned char* tr_records, size_t len)
{
	sgx_status_t status;
	ms_ecall_assign_random_id_t ms;
	ms.ms_tr_records = tr_records;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_initial_sort(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_check_for_sort_correctness(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, NULL);
	return status;
}

