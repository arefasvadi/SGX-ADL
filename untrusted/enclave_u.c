#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_assign_random_id_t {
	unsigned char* ms_tr_records;
	size_t ms_len;
} ms_ecall_assign_random_id_t;

typedef struct ms_ecall_singal_convolution_t {
	int ms_size1;
	int ms_size2;
} ms_ecall_singal_convolution_t;

typedef struct ms_ecall_matrix_mult_t {
	int ms_row1;
	int ms_col1;
	int ms_row2;
	int ms_col2;
} ms_ecall_matrix_mult_t;

typedef struct ms_ecall_init_ptext_imgds_blocking2D_t {
	int ms_single_size_x_bytes;
	int ms_single_size_y_bytes;
	int ms_total_items;
} ms_ecall_init_ptext_imgds_blocking2D_t;

typedef struct ms_ecall_init_ptext_imgds_blocking1D_t {
	int ms_single_size_x_bytes;
	int ms_single_size_y_bytes;
	int ms_total_items;
} ms_ecall_init_ptext_imgds_blocking1D_t;

typedef struct ms_ocall_load_net_config_t {
	const unsigned char* ms_path;
	size_t ms_path_len;
	char* ms_config;
	size_t ms_config_len;
	unsigned int* ms_real_len;
	unsigned char* ms_config_iv;
	unsigned char* ms_config_mac;
} ms_ocall_load_net_config_t;

typedef struct ms_ocall_get_ptext_img_t {
	int ms_loc;
	unsigned char* ms_buff;
	size_t ms_len;
} ms_ocall_get_ptext_img_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_log_t {
	const char* ms_str;
} ms_ocall_print_log_t;

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

typedef struct ms_ocall_get_records_encrypted_t {
	int ms_train_or_test;
	size_t ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
} ms_ocall_get_records_encrypted_t;

typedef struct ms_ocall_set_records_encrypted_t {
	int ms_train_or_test;
	size_t ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
} ms_ocall_set_records_encrypted_t;

typedef struct ms_ocall_get_records_plain_t {
	int ms_train_or_test;
	size_t ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
} ms_ocall_get_records_plain_t;

typedef struct ms_ocall_set_records_plain_t {
	int ms_train_or_test;
	size_t ms_i;
	unsigned char* ms_tr_record_i;
	size_t ms_len_i;
} ms_ocall_set_records_plain_t;

typedef struct ms_ocall_set_timing_t {
	const char* ms_time_id;
	size_t ms_len;
	int ms_is_it_first_call;
	int ms_is_it_last_call;
} ms_ocall_set_timing_t;

typedef struct ms_ocall_write_block_t {
	int64_t ms_block_id;
	size_t ms_index;
	unsigned char* ms_buff;
	size_t ms_len;
} ms_ocall_write_block_t;

typedef struct ms_ocall_read_block_t {
	int64_t ms_block_id;
	size_t ms_index;
	unsigned char* ms_buff;
	size_t ms_len;
} ms_ocall_read_block_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL enclave_ocall_load_net_config(void* pms)
{
	ms_ocall_load_net_config_t* ms = SGX_CAST(ms_ocall_load_net_config_t*, pms);
	ocall_load_net_config(ms->ms_path, ms->ms_path_len, ms->ms_config, ms->ms_config_len, ms->ms_real_len, ms->ms_config_iv, ms->ms_config_mac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_get_ptext_img(void* pms)
{
	ms_ocall_get_ptext_img_t* ms = SGX_CAST(ms_ocall_get_ptext_img_t*, pms);
	ocall_get_ptext_img(ms->ms_loc, ms->ms_buff, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_log(void* pms)
{
	ms_ocall_print_log_t* ms = SGX_CAST(ms_ocall_print_log_t*, pms);
	ocall_print_log(ms->ms_str);

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

static sgx_status_t SGX_CDECL enclave_ocall_get_records_encrypted(void* pms)
{
	ms_ocall_get_records_encrypted_t* ms = SGX_CAST(ms_ocall_get_records_encrypted_t*, pms);
	ocall_get_records_encrypted(ms->ms_train_or_test, ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_set_records_encrypted(void* pms)
{
	ms_ocall_set_records_encrypted_t* ms = SGX_CAST(ms_ocall_set_records_encrypted_t*, pms);
	ocall_set_records_encrypted(ms->ms_train_or_test, ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_get_records_plain(void* pms)
{
	ms_ocall_get_records_plain_t* ms = SGX_CAST(ms_ocall_get_records_plain_t*, pms);
	ocall_get_records_plain(ms->ms_train_or_test, ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_set_records_plain(void* pms)
{
	ms_ocall_set_records_plain_t* ms = SGX_CAST(ms_ocall_set_records_plain_t*, pms);
	ocall_set_records_plain(ms->ms_train_or_test, ms->ms_i, ms->ms_tr_record_i, ms->ms_len_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_set_timing(void* pms)
{
	ms_ocall_set_timing_t* ms = SGX_CAST(ms_ocall_set_timing_t*, pms);
	ocall_set_timing(ms->ms_time_id, ms->ms_len, ms->ms_is_it_first_call, ms->ms_is_it_last_call);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_write_block(void* pms)
{
	ms_ocall_write_block_t* ms = SGX_CAST(ms_ocall_write_block_t*, pms);
	ocall_write_block(ms->ms_block_id, ms->ms_index, ms->ms_buff, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_read_block(void* pms)
{
	ms_ocall_read_block_t* ms = SGX_CAST(ms_ocall_read_block_t*, pms);
	ocall_read_block(ms->ms_block_id, ms->ms_index, ms->ms_buff, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[18];
} ocall_table_enclave = {
	18,
	{
		(void*)enclave_ocall_load_net_config,
		(void*)enclave_ocall_get_ptext_img,
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_print_log,
		(void*)enclave_ocall_get_record_sort,
		(void*)enclave_ocall_set_record_sort,
		(void*)enclave_ocall_get_records_encrypted,
		(void*)enclave_ocall_set_records_encrypted,
		(void*)enclave_ocall_get_records_plain,
		(void*)enclave_ocall_set_records_plain,
		(void*)enclave_ocall_set_timing,
		(void*)enclave_ocall_write_block,
		(void*)enclave_ocall_read_block,
		(void*)enclave_sgx_oc_cpuidex,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
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

sgx_status_t ecall_start_training(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_singal_convolution(sgx_enclave_id_t eid, int size1, int size2)
{
	sgx_status_t status;
	ms_ecall_singal_convolution_t ms;
	ms.ms_size1 = size1;
	ms.ms_size2 = size2;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_matrix_mult(sgx_enclave_id_t eid, int row1, int col1, int row2, int col2)
{
	sgx_status_t status;
	ms_ecall_matrix_mult_t ms;
	ms.ms_row1 = row1;
	ms.ms_col1 = col1;
	ms.ms_row2 = row2;
	ms.ms_col2 = col2;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_init_ptext_imgds_blocking2D(sgx_enclave_id_t eid, int single_size_x_bytes, int single_size_y_bytes, int total_items)
{
	sgx_status_t status;
	ms_ecall_init_ptext_imgds_blocking2D_t ms;
	ms.ms_single_size_x_bytes = single_size_x_bytes;
	ms.ms_single_size_y_bytes = single_size_y_bytes;
	ms.ms_total_items = total_items;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_init_ptext_imgds_blocking1D(sgx_enclave_id_t eid, int single_size_x_bytes, int single_size_y_bytes, int total_items)
{
	sgx_status_t status;
	ms_ecall_init_ptext_imgds_blocking1D_t ms;
	ms.ms_single_size_x_bytes = single_size_x_bytes;
	ms.ms_single_size_y_bytes = single_size_y_bytes;
	ms.ms_total_items = total_items;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	return status;
}

