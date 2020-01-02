#pragma once
#include <deque>
#include "rand/PRNG.h"
#include "common-structures.h"


#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/minireflect.h>
#include <flatbuffers/reflection.h>
#include "fbs_gen_code/taskconfig_generated.h"
#include "fbs_gen_code/aes128gcm_generated.h"
#include "flats-util.hpp"

#ifndef ONLY_GPU
#include "sgx_defs.h"
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */
#include "sgx_uae_service.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"

extern sgx_enclave_id_t         global_eid; /* global enclave id */
extern sgx_uswitchless_config_t us_config;

#endif
#include "App-Types.h"



extern FlatBufferedContainerT<TrainLocationsConfigs>   trainlocconfigs;
extern FlatBufferedContainerT<PredictLocationsConfigs> predlocconfigs;
extern FlatBufferedContainerT<DataConfig> dsconfigs;
extern FlatBufferedContainerT<ArchConfig> archconfigs;
extern train_batch_step_report_snapshot_fbv_t train_iterations_snapshots;
// extern std::vector<uint8_t> trainlocconfigs_bytes;
// extern std::vector<uint8_t> predlocconfigs_bytes;

struct network;
/*
I know global vars are a horrible solution! Later I will create factory classes!
*/

extern bool                      global_training;

extern int gpu_index;
extern RunConfig                run_config;

extern std::unique_ptr<PRNG> pub_root_rng;
extern std::deque<std::vector<uint8_t>> enc_integ_set;
extern std::deque<std::vector<uint8_t>> dec_img_set;
extern std::shared_ptr<network> network_;
extern std::shared_ptr<PRNG> batch_inp_rng;
extern std::shared_ptr<PRNG> batch_layers_rng;
extern train_batch_step_report_snapshot_fbv_t train_iterations_snapshots;
extern train_batch_step_snapshot_snapshot_frbv_t enclave_train_iterations_snapshots;
//extern std::unordered_map<, >
#ifdef MEASURE_SWITCHLESS_TIMING
extern uint64_t g_stats[4];
void
exit_callback(sgx_uswitchless_worker_type_t         type,
              sgx_uswitchless_worker_event_t        event,
              const sgx_uswitchless_worker_stats_t* stats);
void
print_switchless_timing();
#endif