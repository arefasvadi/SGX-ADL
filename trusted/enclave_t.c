#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_enclave_init(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_enclave_init();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_assign_random_id(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_assign_random_id_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_assign_random_id_t* ms = SGX_CAST(ms_ecall_assign_random_id_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_tr_records = ms->ms_tr_records;
	size_t _tmp_len = ms->ms_len;
	size_t _len_tr_records = _tmp_len;
	unsigned char* _in_tr_records = NULL;

	CHECK_UNIQUE_POINTER(_tmp_tr_records, _len_tr_records);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_tr_records != NULL && _len_tr_records != 0) {
		if ( _len_tr_records % sizeof(*_tmp_tr_records) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tr_records = (unsigned char*)malloc(_len_tr_records);
		if (_in_tr_records == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tr_records, _len_tr_records, _tmp_tr_records, _len_tr_records)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_assign_random_id(_in_tr_records, _tmp_len);
	if (_in_tr_records) {
		if (memcpy_s(_tmp_tr_records, _len_tr_records, _in_tr_records, _len_tr_records)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_tr_records) free(_in_tr_records);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_initial_sort(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_initial_sort();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_check_for_sort_correctness(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_check_for_sort_correctness();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_start_training(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_start_training();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_singal_convolution(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_singal_convolution_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_singal_convolution_t* ms = SGX_CAST(ms_ecall_singal_convolution_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_singal_convolution(ms->ms_size1, ms->ms_size2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_matrix_mult(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_matrix_mult_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_matrix_mult_t* ms = SGX_CAST(ms_ecall_matrix_mult_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_matrix_mult(ms->ms_row1, ms->ms_col1, ms->ms_row2, ms->ms_col2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_ptext_imgds_blocking2D(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_ptext_imgds_blocking2D_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_ptext_imgds_blocking2D_t* ms = SGX_CAST(ms_ecall_init_ptext_imgds_blocking2D_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_init_ptext_imgds_blocking2D(ms->ms_single_size_x_bytes, ms->ms_single_size_y_bytes, ms->ms_total_items);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_ptext_imgds_blocking1D(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_ptext_imgds_blocking1D_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_ptext_imgds_blocking1D_t* ms = SGX_CAST(ms_ecall_init_ptext_imgds_blocking1D_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_init_ptext_imgds_blocking1D(ms->ms_single_size_x_bytes, ms->ms_single_size_y_bytes, ms->ms_total_items);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_ecall_enclave_init, 0},
		{(void*)(uintptr_t)sgx_ecall_assign_random_id, 0},
		{(void*)(uintptr_t)sgx_ecall_initial_sort, 0},
		{(void*)(uintptr_t)sgx_ecall_check_for_sort_correctness, 0},
		{(void*)(uintptr_t)sgx_ecall_start_training, 0},
		{(void*)(uintptr_t)sgx_ecall_singal_convolution, 0},
		{(void*)(uintptr_t)sgx_ecall_matrix_mult, 0},
		{(void*)(uintptr_t)sgx_ecall_init_ptext_imgds_blocking2D, 0},
		{(void*)(uintptr_t)sgx_ecall_init_ptext_imgds_blocking1D, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[18][9];
} g_dyn_entry_table = {
	18,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_load_net_config(const unsigned char* path, size_t path_len, char* config, size_t config_len, unsigned int* real_len, unsigned char* config_iv, unsigned char* config_mac)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path_len;
	size_t _len_config = config_len;
	size_t _len_real_len = sizeof(unsigned int);
	size_t _len_config_iv = 12;
	size_t _len_config_mac = 16;

	ms_ocall_load_net_config_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_net_config_t);
	void *__tmp = NULL;

	void *__tmp_config = NULL;
	void *__tmp_real_len = NULL;
	void *__tmp_config_iv = NULL;
	void *__tmp_config_mac = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(config, _len_config);
	CHECK_ENCLAVE_POINTER(real_len, _len_real_len);
	CHECK_ENCLAVE_POINTER(config_iv, _len_config_iv);
	CHECK_ENCLAVE_POINTER(config_mac, _len_config_mac);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (config != NULL) ? _len_config : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (real_len != NULL) ? _len_real_len : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (config_iv != NULL) ? _len_config_iv : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (config_mac != NULL) ? _len_config_mac : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_net_config_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_net_config_t));
	ocalloc_size -= sizeof(ms_ocall_load_net_config_t);

	if (path != NULL) {
		ms->ms_path = (const unsigned char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_path_len = path_len;
	if (config != NULL) {
		ms->ms_config = (char*)__tmp;
		__tmp_config = __tmp;
		if (_len_config % sizeof(*config) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_config, 0, _len_config);
		__tmp = (void *)((size_t)__tmp + _len_config);
		ocalloc_size -= _len_config;
	} else {
		ms->ms_config = NULL;
	}
	
	ms->ms_config_len = config_len;
	if (real_len != NULL) {
		ms->ms_real_len = (unsigned int*)__tmp;
		__tmp_real_len = __tmp;
		if (_len_real_len % sizeof(*real_len) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_real_len, 0, _len_real_len);
		__tmp = (void *)((size_t)__tmp + _len_real_len);
		ocalloc_size -= _len_real_len;
	} else {
		ms->ms_real_len = NULL;
	}
	
	if (config_iv != NULL) {
		ms->ms_config_iv = (unsigned char*)__tmp;
		__tmp_config_iv = __tmp;
		if (_len_config_iv % sizeof(*config_iv) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_config_iv, 0, _len_config_iv);
		__tmp = (void *)((size_t)__tmp + _len_config_iv);
		ocalloc_size -= _len_config_iv;
	} else {
		ms->ms_config_iv = NULL;
	}
	
	if (config_mac != NULL) {
		ms->ms_config_mac = (unsigned char*)__tmp;
		__tmp_config_mac = __tmp;
		if (_len_config_mac % sizeof(*config_mac) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_config_mac, 0, _len_config_mac);
		__tmp = (void *)((size_t)__tmp + _len_config_mac);
		ocalloc_size -= _len_config_mac;
	} else {
		ms->ms_config_mac = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (config) {
			if (memcpy_s((void*)config, _len_config, __tmp_config, _len_config)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (real_len) {
			if (memcpy_s((void*)real_len, _len_real_len, __tmp_real_len, _len_real_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (config_iv) {
			if (memcpy_s((void*)config_iv, _len_config_iv, __tmp_config_iv, _len_config_iv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (config_mac) {
			if (memcpy_s((void*)config_mac, _len_config_mac, __tmp_config_mac, _len_config_mac)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_ptext_img(int loc, unsigned char* buff, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buff = len;

	ms_ocall_get_ptext_img_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_ptext_img_t);
	void *__tmp = NULL;

	void *__tmp_buff = NULL;

	CHECK_ENCLAVE_POINTER(buff, _len_buff);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buff != NULL) ? _len_buff : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_ptext_img_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_ptext_img_t));
	ocalloc_size -= sizeof(ms_ocall_get_ptext_img_t);

	ms->ms_loc = loc;
	if (buff != NULL) {
		ms->ms_buff = (unsigned char*)__tmp;
		__tmp_buff = __tmp;
		if (_len_buff % sizeof(*buff) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buff, 0, _len_buff);
		__tmp = (void *)((size_t)__tmp + _len_buff);
		ocalloc_size -= _len_buff;
	} else {
		ms->ms_buff = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (buff) {
			if (memcpy_s((void*)buff, _len_buff, __tmp_buff, _len_buff)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_log(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_log_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_log_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_log_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_log_t));
	ocalloc_size -= sizeof(ms_ocall_print_log_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_record_sort(int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tr_record_i = len_i;
	size_t _len_tr_record_j = len_j;

	ms_ocall_get_record_sort_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_record_sort_t);
	void *__tmp = NULL;

	void *__tmp_tr_record_i = NULL;
	void *__tmp_tr_record_j = NULL;

	CHECK_ENCLAVE_POINTER(tr_record_i, _len_tr_record_i);
	CHECK_ENCLAVE_POINTER(tr_record_j, _len_tr_record_j);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_i != NULL) ? _len_tr_record_i : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_j != NULL) ? _len_tr_record_j : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_record_sort_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_record_sort_t));
	ocalloc_size -= sizeof(ms_ocall_get_record_sort_t);

	ms->ms_i = i;
	if (tr_record_i != NULL) {
		ms->ms_tr_record_i = (unsigned char*)__tmp;
		__tmp_tr_record_i = __tmp;
		if (_len_tr_record_i % sizeof(*tr_record_i) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_tr_record_i, 0, _len_tr_record_i);
		__tmp = (void *)((size_t)__tmp + _len_tr_record_i);
		ocalloc_size -= _len_tr_record_i;
	} else {
		ms->ms_tr_record_i = NULL;
	}
	
	ms->ms_len_i = len_i;
	ms->ms_j = j;
	if (tr_record_j != NULL) {
		ms->ms_tr_record_j = (unsigned char*)__tmp;
		__tmp_tr_record_j = __tmp;
		if (_len_tr_record_j % sizeof(*tr_record_j) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_tr_record_j, 0, _len_tr_record_j);
		__tmp = (void *)((size_t)__tmp + _len_tr_record_j);
		ocalloc_size -= _len_tr_record_j;
	} else {
		ms->ms_tr_record_j = NULL;
	}
	
	ms->ms_len_j = len_j;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (tr_record_i) {
			if (memcpy_s((void*)tr_record_i, _len_tr_record_i, __tmp_tr_record_i, _len_tr_record_i)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (tr_record_j) {
			if (memcpy_s((void*)tr_record_j, _len_tr_record_j, __tmp_tr_record_j, _len_tr_record_j)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_set_record_sort(int i, unsigned char* tr_record_i, size_t len_i, int j, unsigned char* tr_record_j, size_t len_j)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tr_record_i = len_i;
	size_t _len_tr_record_j = len_j;

	ms_ocall_set_record_sort_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_set_record_sort_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(tr_record_i, _len_tr_record_i);
	CHECK_ENCLAVE_POINTER(tr_record_j, _len_tr_record_j);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_i != NULL) ? _len_tr_record_i : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_j != NULL) ? _len_tr_record_j : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_set_record_sort_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_set_record_sort_t));
	ocalloc_size -= sizeof(ms_ocall_set_record_sort_t);

	ms->ms_i = i;
	if (tr_record_i != NULL) {
		ms->ms_tr_record_i = (unsigned char*)__tmp;
		if (_len_tr_record_i % sizeof(*tr_record_i) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, tr_record_i, _len_tr_record_i)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_tr_record_i);
		ocalloc_size -= _len_tr_record_i;
	} else {
		ms->ms_tr_record_i = NULL;
	}
	
	ms->ms_len_i = len_i;
	ms->ms_j = j;
	if (tr_record_j != NULL) {
		ms->ms_tr_record_j = (unsigned char*)__tmp;
		if (_len_tr_record_j % sizeof(*tr_record_j) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, tr_record_j, _len_tr_record_j)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_tr_record_j);
		ocalloc_size -= _len_tr_record_j;
	} else {
		ms->ms_tr_record_j = NULL;
	}
	
	ms->ms_len_j = len_j;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_records_encrypted(int train_or_test, size_t i, unsigned char* tr_record_i, size_t len_i)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tr_record_i = len_i;

	ms_ocall_get_records_encrypted_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_records_encrypted_t);
	void *__tmp = NULL;

	void *__tmp_tr_record_i = NULL;

	CHECK_ENCLAVE_POINTER(tr_record_i, _len_tr_record_i);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_i != NULL) ? _len_tr_record_i : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_records_encrypted_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_records_encrypted_t));
	ocalloc_size -= sizeof(ms_ocall_get_records_encrypted_t);

	ms->ms_train_or_test = train_or_test;
	ms->ms_i = i;
	if (tr_record_i != NULL) {
		ms->ms_tr_record_i = (unsigned char*)__tmp;
		__tmp_tr_record_i = __tmp;
		if (_len_tr_record_i % sizeof(*tr_record_i) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_tr_record_i, 0, _len_tr_record_i);
		__tmp = (void *)((size_t)__tmp + _len_tr_record_i);
		ocalloc_size -= _len_tr_record_i;
	} else {
		ms->ms_tr_record_i = NULL;
	}
	
	ms->ms_len_i = len_i;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (tr_record_i) {
			if (memcpy_s((void*)tr_record_i, _len_tr_record_i, __tmp_tr_record_i, _len_tr_record_i)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_set_records_encrypted(int train_or_test, size_t i, unsigned char* tr_record_i, size_t len_i)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tr_record_i = len_i;

	ms_ocall_set_records_encrypted_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_set_records_encrypted_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(tr_record_i, _len_tr_record_i);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_i != NULL) ? _len_tr_record_i : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_set_records_encrypted_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_set_records_encrypted_t));
	ocalloc_size -= sizeof(ms_ocall_set_records_encrypted_t);

	ms->ms_train_or_test = train_or_test;
	ms->ms_i = i;
	if (tr_record_i != NULL) {
		ms->ms_tr_record_i = (unsigned char*)__tmp;
		if (_len_tr_record_i % sizeof(*tr_record_i) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, tr_record_i, _len_tr_record_i)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_tr_record_i);
		ocalloc_size -= _len_tr_record_i;
	} else {
		ms->ms_tr_record_i = NULL;
	}
	
	ms->ms_len_i = len_i;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_records_plain(int train_or_test, size_t i, unsigned char* tr_record_i, size_t len_i)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tr_record_i = len_i;

	ms_ocall_get_records_plain_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_records_plain_t);
	void *__tmp = NULL;

	void *__tmp_tr_record_i = NULL;

	CHECK_ENCLAVE_POINTER(tr_record_i, _len_tr_record_i);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_i != NULL) ? _len_tr_record_i : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_records_plain_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_records_plain_t));
	ocalloc_size -= sizeof(ms_ocall_get_records_plain_t);

	ms->ms_train_or_test = train_or_test;
	ms->ms_i = i;
	if (tr_record_i != NULL) {
		ms->ms_tr_record_i = (unsigned char*)__tmp;
		__tmp_tr_record_i = __tmp;
		if (_len_tr_record_i % sizeof(*tr_record_i) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_tr_record_i, 0, _len_tr_record_i);
		__tmp = (void *)((size_t)__tmp + _len_tr_record_i);
		ocalloc_size -= _len_tr_record_i;
	} else {
		ms->ms_tr_record_i = NULL;
	}
	
	ms->ms_len_i = len_i;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (tr_record_i) {
			if (memcpy_s((void*)tr_record_i, _len_tr_record_i, __tmp_tr_record_i, _len_tr_record_i)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_set_records_plain(int train_or_test, size_t i, unsigned char* tr_record_i, size_t len_i)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tr_record_i = len_i;

	ms_ocall_set_records_plain_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_set_records_plain_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(tr_record_i, _len_tr_record_i);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tr_record_i != NULL) ? _len_tr_record_i : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_set_records_plain_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_set_records_plain_t));
	ocalloc_size -= sizeof(ms_ocall_set_records_plain_t);

	ms->ms_train_or_test = train_or_test;
	ms->ms_i = i;
	if (tr_record_i != NULL) {
		ms->ms_tr_record_i = (unsigned char*)__tmp;
		if (_len_tr_record_i % sizeof(*tr_record_i) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, tr_record_i, _len_tr_record_i)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_tr_record_i);
		ocalloc_size -= _len_tr_record_i;
	} else {
		ms->ms_tr_record_i = NULL;
	}
	
	ms->ms_len_i = len_i;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_set_timing(const char* time_id, size_t len, int is_it_first_call, int is_it_last_call)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time_id = len;

	ms_ocall_set_timing_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_set_timing_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(time_id, _len_time_id);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time_id != NULL) ? _len_time_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_set_timing_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_set_timing_t));
	ocalloc_size -= sizeof(ms_ocall_set_timing_t);

	if (time_id != NULL) {
		ms->ms_time_id = (const char*)__tmp;
		if (_len_time_id % sizeof(*time_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, time_id, _len_time_id)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_time_id);
		ocalloc_size -= _len_time_id;
	} else {
		ms->ms_time_id = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_is_it_first_call = is_it_first_call;
	ms->ms_is_it_last_call = is_it_last_call;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_block(int64_t block_id, size_t index, unsigned char* buff, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buff = len;

	ms_ocall_write_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_block_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buff, _len_buff);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buff != NULL) ? _len_buff : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_block_t));
	ocalloc_size -= sizeof(ms_ocall_write_block_t);

	ms->ms_block_id = block_id;
	ms->ms_index = index;
	if (buff != NULL) {
		ms->ms_buff = (unsigned char*)__tmp;
		if (_len_buff % sizeof(*buff) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buff, _len_buff)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buff);
		ocalloc_size -= _len_buff;
	} else {
		ms->ms_buff = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_block(int64_t block_id, size_t index, unsigned char* buff, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buff = len;

	ms_ocall_read_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_block_t);
	void *__tmp = NULL;

	void *__tmp_buff = NULL;

	CHECK_ENCLAVE_POINTER(buff, _len_buff);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buff != NULL) ? _len_buff : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_block_t));
	ocalloc_size -= sizeof(ms_ocall_read_block_t);

	ms->ms_block_id = block_id;
	ms->ms_index = index;
	if (buff != NULL) {
		ms->ms_buff = (unsigned char*)__tmp;
		__tmp_buff = __tmp;
		if (_len_buff % sizeof(*buff) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buff, 0, _len_buff);
		__tmp = (void *)((size_t)__tmp + _len_buff);
		ocalloc_size -= _len_buff;
	} else {
		ms->ms_buff = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (buff) {
			if (memcpy_s((void*)buff, _len_buff, __tmp_buff, _len_buff)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

