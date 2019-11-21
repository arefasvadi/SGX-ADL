#pragma once

#include <assert.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/minireflect.h>
#include <flatbuffers/reflection.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <deque>
#include <string>
#include <vector>
#include "sgx_defs.h"
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */
#include "sgx_uae_service.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"
#include "common-structures.h"
#include "global-vars-untrusted.h"
#include "enclave_u.h"
#include "fbs_gen_code/taskconfig_generated.h"
#include "fbs_gen_code/aes128gcm_generated.h"
#include "flats-util.hpp"
#include "load-image.h"
#include "rand/PRNG.h"

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

RunConfig
process_json_config(const std::string& f_path);

int
initialize_enclave();

sgx_status_t
dest_enclave(const sgx_enclave_id_t enclave_id);

void
print_timers();

// void
// parse_location_configs(const std::string& location_conf_file,
//                        const std::string& tasktype);
void
prepare_enclave(const std::string& location_conf_file,
                const std::string& tasktype);

void prepare_gpu();

void
main_logger(int level, const char* file, int line, const char* format, ...);

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif
