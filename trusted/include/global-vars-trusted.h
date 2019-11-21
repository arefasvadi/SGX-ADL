#include "Enclave-Types.h"
#include "common-structures.h"
#include "sgx_tcrypto.h"
#include "flatbuffers/flatbuffers.h"
#include "fbs_gen_code/taskconfig_generated.h"
#include "fbs_gen_code/signedECC_generated.h"
#include "flats-util.hpp"
#include "rand/PRNG.h"
#include <deque>
struct network;
/*
I know global vars are a horrible solution! Later I will create factory classes!
*/

extern int gpu_index ;
extern CommonRunConfig comm_run_config;
extern int printf(const char *fmt, ...);

extern sgx_aes_gcm_128bit_key_t enclave_ases_gcm_key;
extern sgx_cmac_128bit_key_t enclave_cmac_key;
extern sgx_aes_gcm_128bit_key_t client_ases_gcm_key;

extern sgx_ec256_public_t enclave_sig_pk_key;
extern sgx_ec256_private_t enclave_sig_sk_key;
extern sgx_ec256_public_t client_sig_pk_key;

extern uint64_t session_id;

extern FlatBufferedContainerT<TaskConfig> task_config;
extern FlatBufferedContainerT<DataConfig> dsconfigs;
extern FlatBufferedContainerT<ArchConfig> archconfigs;

extern std::unique_ptr<PRNG> sgx_root_rng;
extern std::unique_ptr<PRNG> pub_root_rng;
extern std::deque<uint32_t> integ_set_ids;

extern integrity_set_func choose_integrity_set;
extern std::unique_ptr<net_init_load_net_func> net_init_loader_ptr;
extern std::unique_ptr<integ_verf_variations> verf_scheme_ptr;

extern std::shared_ptr<network> network_;