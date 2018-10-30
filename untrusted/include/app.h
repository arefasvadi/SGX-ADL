#pragma once

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "load-image.h"
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */

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

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif
