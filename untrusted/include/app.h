#pragma once

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "common-structures.h"
#include "load-image.h"
#include "sgx_defs.h"
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */
#include "enclave_u.h"
#include "sgx_uae_service.h"
#include "sgx_urts.h"


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__GNUC__)
#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "sgxdnn.enclave.signed.so"
#endif

extern sgx_enclave_id_t global_eid; /* global enclave id */
extern RunConfig run_config;

RunConfig process_json_config(const std::string &f_path);
int initialize_enclave(void);
sgx_status_t dest_enclave(const sgx_enclave_id_t enclave_id);
void print_timers();
int initialize_enclave(void);

void main_logger(int level, const char *file, int line, const char *format,
                 ...);

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif
