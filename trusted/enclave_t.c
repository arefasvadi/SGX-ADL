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

static sgx_status_t SGX_CDECL sgx_ecall_enclave_init(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_enclave_init();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_enclave_init, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][1];
} g_dyn_entry_table = {
	2,
	{
		{0, },
		{0, },
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

	ocalloc_size += (path != NULL) ? _len_path : 0;
	ocalloc_size += (config != NULL) ? _len_config : 0;
	ocalloc_size += (real_len != NULL) ? _len_real_len : 0;
	ocalloc_size += (config_iv != NULL) ? _len_config_iv : 0;
	ocalloc_size += (config_mac != NULL) ? _len_config_mac : 0;

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
		memset(__tmp_real_len, 0, _len_real_len);
		__tmp = (void *)((size_t)__tmp + _len_real_len);
		ocalloc_size -= _len_real_len;
	} else {
		ms->ms_real_len = NULL;
	}
	
	if (config_iv != NULL) {
		ms->ms_config_iv = (unsigned char*)__tmp;
		__tmp_config_iv = __tmp;
		memset(__tmp_config_iv, 0, _len_config_iv);
		__tmp = (void *)((size_t)__tmp + _len_config_iv);
		ocalloc_size -= _len_config_iv;
	} else {
		ms->ms_config_iv = NULL;
	}
	
	if (config_mac != NULL) {
		ms->ms_config_mac = (unsigned char*)__tmp;
		__tmp_config_mac = __tmp;
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

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	ocalloc_size += (str != NULL) ? _len_str : 0;

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
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

