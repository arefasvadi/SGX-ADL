#pragma once

#include <assert.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/minireflect.h>
#include <flatbuffers/reflection.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "common-structures.h"
#include "enclave_u.h"
#include "fbs_gen_code/taskconfig_generated.h"
#include "flats-util.hpp"
#include "load-image.h"
#include "sgx_defs.h"
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */
#include "sgx_uae_service.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"

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

extern sgx_enclave_id_t         global_eid; /* global enclave id */
extern RunConfig                run_config;
extern sgx_uswitchless_config_t us_config;
extern FlatBufferedContainerT<TrainLocationsConfigs>   trainlocconfigs;
extern FlatBufferedContainerT<PredictLocationsConfigs> predlocconfigs;
// extern std::vector<uint8_t> trainlocconfigs_bytes;
// extern std::vector<uint8_t> predlocconfigs_bytes;

#ifdef MEASURE_SWITCHLESS_TIMING
extern uint64_t g_stats[4];
void
exit_callback(sgx_uswitchless_worker_type_t         type,
              sgx_uswitchless_worker_event_t        event,
              const sgx_uswitchless_worker_stats_t* stats);
void
print_switchless_timing();
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
void
main_logger(int level, const char* file, int line, const char* format, ...);

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif
