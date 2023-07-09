#include "enclave-app.h"

#include "common.h"
#include "darknet-addons.h"
#include "../../enclave_t.h"
#include "util.h"
#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
#include <BlockEngine.hpp>
#endif
#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include "timingdefs.h"
#include "hexString.h"
// #include "immintrin.h"
#include "ipp/ippcp.h"
#include "prepare-dnnl.h"
#include "rand/PRNG.h"
// #include "x86intrin.h"

// #include <x86intrin.h>

bool global_training = true;

int             gpu_index       = -1;
CommonRunConfig comm_run_config = {};

sgx_aes_gcm_128bit_key_t enclave_ases_gcm_key;
sgx_cmac_128bit_key_t    enclave_cmac_key;
sgx_aes_gcm_128bit_key_t client_ases_gcm_key;
sgx_ec256_public_t       enclave_sig_pk_key;
sgx_ec256_private_t      enclave_sig_sk_key;
sgx_ec256_public_t       client_sig_pk_key;

uint64_t                session_id;
uint32_t                plain_dataset_size;
uint32_t                integrity_set_dataset_size;
std::unique_ptr<size_t> plain_image_label_auth_bytes;
std::unique_ptr<size_t> enc_image_label_auth_bytes;

FlatBufferedContainerT<TaskConfig> task_config = {};
FlatBufferedContainerT<DataConfig> dsconfigs   = {};
FlatBufferedContainerT<ArchConfig> archconfigs = {};

std::unique_ptr<PRNG> sgx_root_rng = nullptr;
std::unique_ptr<PRNG> pub_root_rng = nullptr;

std::deque<uint32_t> integ_set_ids;

integrity_set_func                      choose_integrity_set = {};
std::unique_ptr<net_init_load_net_func> net_init_loader_ptr  = nullptr;
std::unique_ptr<net_context_variations> net_context_         = nullptr;

// std::unique_ptr<verf_variations_t>  verf_scheme_ptr      = nullptr;
std::shared_ptr<network>                 network_      = nullptr;
std::shared_ptr<network>                 verf_network_ = nullptr;
std::unique_ptr<verf_variations_t>       main_verf_task_variation_;
moodycamel::ConcurrentQueue<verf_task_t> task_queue;

int total_items  = 0;
int single_len_x = 0;
int single_leb_y = 0;

template <typename T>
T
swap_endian(T u) {
  static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

  union {
    T             u;
    unsigned char u8[sizeof(T)];
  } source, dest;

  source.u = u;

  for (size_t k = 0; k < sizeof(T); k++)
    dest.u8[k] = source.u8[sizeof(T) - k - 1];

  return dest.u;
}

int
printf(const char *fmt, ...) {
  char    buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
  return 0;
}

/*!
 * Helper function to compare expected and actual function return statuses and
 * display an error mesage if those are different.
 *
 * \param[in] Function name to display
 * \param[in] Expected status
 * \param[in] Actual status
 *
 * \return zero if statuses are not equal, otherwise - non-zero value
 */
static int
checkStatus(const char *funcName, IppStatus expectedStatus, IppStatus status) {
  if (expectedStatus != status) {
    LOG_ERROR("%s: unexpected return status\n", funcName);
    LOG_ERROR("Expected: %s\n", ippcpGetStatusString(expectedStatus));
    LOG_ERROR("Received: %s\n", ippcpGetStatusString(status));
    return 0;
  }
  return 1;
}

void
ecall_NOT_SECURE_send_req_keys(uint8_t *cl_pksig,
                               size_t   cl_pksig_len,
                               uint8_t *cl_sksymm,
                               size_t   cl_sksymm_len,
                               uint8_t *sgx_pksig,
                               size_t   sgx_pksig_len,
                               uint8_t *sgx_sksig,
                               size_t   sgx_sksig_len,
                               uint8_t *sgx_sksymm,
                               size_t   sgx_sksymm_len) {
  if (cl_pksig_len != sizeof(client_sig_pk_key)
      || cl_sksymm_len != SGX_AESGCM_KEY_SIZE) {
    LOG_ERROR("clients sig key size or symmetric key size does not match!\n")
    abort();
  }
  memcpy(&client_sig_pk_key, cl_pksig, sizeof(client_sig_pk_key));

  // client_sig_pk_key = swap_endian<sgx_ec256_public_t>(client_sig_pk_key);

  auto hex_gx   = bytesToHexString(client_sig_pk_key.gx, SGX_ECP256_KEY_SIZE);
  auto hex_gy   = bytesToHexString(client_sig_pk_key.gy, SGX_ECP256_KEY_SIZE);
  auto both_gxy = bytesToHexString((uint8_t *)&client_sig_pk_key,
                                   sizeof(client_sig_pk_key));
  LOG_DEBUG(
      "client sig pk:\n"
      "gx :\t<\"%s\">\n"
      "gy :\t<\"%s\">\n"
      "gxy:\t<\"%s\">\n",
      hex_gx.c_str(),
      hex_gy.c_str(),
      both_gxy.c_str())

  sgx_ecc_state_handle_t ecc_handle  = nullptr;
  int                    valid_point = 0;
  auto                   ret         = sgx_ecc256_open_context(&ecc_handle);
  CHECK_SGX_SUCCESS(ret, "Openning ECC handle for Signature Caused Problem\n")
  ret = sgx_ecc256_check_point(&client_sig_pk_key, ecc_handle, &valid_point);
  CHECK_SGX_SUCCESS(ret, "Calling ecc256 check point caused problem\n")
  if (valid_point == 0) {
    LOG_WARN("FIXME!\nNot a valid point on curve!\n")
    // abort();
  }
  ret = sgx_ecc256_close_context(ecc_handle);
  CHECK_SGX_SUCCESS(
      ret, "Closing ECC handle for Task Config Signature Caused Problem\n")

  memcpy(client_ases_gcm_key, cl_sksymm, cl_sksymm_len);
  if (sgx_pksig_len != sizeof(enclave_sig_pk_key)
      || sgx_sksig_len != sizeof(enclave_sig_sk_key)
      || sgx_sksymm_len != SGX_AESGCM_KEY_SIZE) {
    LOG_ERROR("sgx's sig key size or symmetric key size does not match!\n")
    abort();
  }

  memcpy(&enclave_sig_pk_key, sgx_pksig, sgx_pksig_len);
  memcpy(&enclave_sig_sk_key, sgx_sksig, sgx_sksig_len);
  memcpy(enclave_ases_gcm_key, sgx_sksymm, sgx_sksymm_len);
  memcpy(enclave_cmac_key, sgx_sksymm, sgx_sksymm_len);
}

void
ecall_send_signed_task_config_verify(uint8_t *task_conf,
                                     size_t   task_conf_len,
                                     int      verf_type) {
  auto task_config_w_sig = flatbuffers::GetMutableRoot<SignedECC>(task_conf);
  if (verf_type == (int)verf_variations_t::FRBV) {
    main_verf_task_variation_ = std::unique_ptr<verf_variations_t>(
        new verf_variations_t(verf_variations_t::FRBV));
  } else if (verf_type == (int)verf_variations_t::FRBRMMV) {
    main_verf_task_variation_ = std::unique_ptr<verf_variations_t>(
        new verf_variations_t(verf_variations_t::FRBRMMV));
  }
  // verify sig first
  uint8_t sig_res = SGX_EC_INVALID_SIGNATURE;
  // this one causes stack overrun for our settings! so I'm taking it in heap!
  sgx_ecc_state_handle_t ecc_handle = nullptr;

  auto ret = sgx_ecc256_open_context(&ecc_handle);
  CHECK_SGX_SUCCESS(
      ret, "Openning ECC handle for Task Config Signature Caused Problem\n")
  LOG_DEBUG("task conf buf len: %u, sig buf len: %u\n",
            task_config_w_sig->content()->size(),
            task_config_w_sig->signature()->size())

  if (sizeof(sgx_ec256_signature_t) != task_config_w_sig->signature()->size()) {
    LOG_ERROR("signature size does not match\n expected: %d but got %d",
              sizeof(sgx_ec256_signature_t),
              task_config_w_sig->signature()->size())
    abort();
  }

  ret = sgx_ecdsa_verify(
      task_config_w_sig->content()->data(),
      task_config_w_sig->content()->size(),
      &client_sig_pk_key,
      (sgx_ec256_signature_t *)task_config_w_sig->signature()->Data(),
      &sig_res,
      ecc_handle);
  CHECK_SGX_SUCCESS(
      ret, "Verifying Task Config Signature Caused Problem with sig result\n")
  if (sig_res != SGX_EC_VALID) {
    LOG_WARN("FIXME!\nsig does not match, error code is %u\n", sig_res)
    // abort();
  }

  ret = sgx_ecc256_close_context(ecc_handle);
  CHECK_SGX_SUCCESS(
      ret, "Closing ECC handle for Task Config Signature Caused Problem\n")

  // copy into task object container
  task_config.vecBuff
      = std::vector<uint8_t>(task_config_w_sig->content()->size(), 0);
  std::memcpy(task_config.vecBuff.data(),
              task_config_w_sig->mutable_content()->Data(),
              task_config.vecBuff.size());
  task_config.objPtr
      = flatbuffers::GetMutableRoot<TaskConfig>(task_config.vecBuff.data());

  LOG_DEBUG(
      "Verfied Task Config with:\n>task type: %d\n>security_type: "
      "%d\n>root_seed: %d\n",
      task_config.objPtr->task_type(),
      task_config.objPtr->security_type(),
      task_config.objPtr->pub_root_rand_seed())

  // after task conf config global params must be set
  LOG_WARN(
      "FIXME!\nChoosing integrity selection should be moved to task config by "
      "user\n")

  fix_task_dependent_global_vars();
}

void
ecall_send_arch_cofig_verify_init(uint8_t *arch_conf_buff,
                                  size_t   arch_conf_len) {
  LOG_DEBUG("arch config len is: %u bytes\n", arch_conf_len)
  // create net_conf_object
  archconfigs.vecBuff = std::vector<uint8_t>(arch_conf_len, 0);
  std::memcpy(archconfigs.vecBuff.data(), arch_conf_buff, arch_conf_len);
  archconfigs.objPtr
      = flatbuffers::GetMutableRoot<ArchConfig>(archconfigs.vecBuff.data());
  // verify its hash with task config
  verify_init_net_config();
  // load network depending on the task and security
}

void
ecall_send_data_config_dsverify(uint8_t *ds_conf, size_t ds_conf_len) {
  dsconfigs.vecBuff = std::vector<uint8_t>(ds_conf_len, 0);
  std::memcpy(dsconfigs.vecBuff.data(), ds_conf, ds_conf_len);
  dsconfigs.objPtr
      = flatbuffers::GetMutableRoot<DataConfig>(dsconfigs.vecBuff.data());
  LOG_DEBUG(
      "Dataset contains %d records with <width>:%d, <height>:%d, "
      "<channels>:%d, "
      "<number of classes>:%d\n",
      dsconfigs.objPtr->dataset_size(),
      dsconfigs.objPtr->img_label_meta()->image_meta()->width(),
      dsconfigs.objPtr->img_label_meta()->image_meta()->height(),
      dsconfigs.objPtr->img_label_meta()->image_meta()->channels(),
      dsconfigs.objPtr->img_label_meta()->label_meta()->numClasses())
  verify_init_dataset();
}

void
ecall_start_training() {
  SET_START_TIMING(SGX_TIMING_OVERALL_TRAINING)
  LOG_DEBUG("Starting the training\n")
  const int temp_iter = 1;
#if defined(USE_SGX_LAYERWISE)
  if (*net_context_ == net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT
      && *main_verf_task_variation_ == verf_variations_t::FRBV) {
    for (int i = 1; i <= temp_iter; ++i) {
      start_training_verification_frbv(i);
    }
    // abort();
  } else if (*net_context_
                 == net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT
             && *main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
    for (int i = 1; i <= temp_iter; ++i) {
      start_training_verification_frbmmv(i);
    }
    // abort();
  } else if (*net_context_
             == net_context_variations::
                 TRAINING_PRIVACY_INTEGRITY_LAYERED_FIT) {
    for (int i = 1; i <= temp_iter; ++i) {
      start_training_in_sgx(i);
    }
  }
#elif defined(USE_SGX_PURE)
  if (*net_context_
          == net_context_variations::TRAINING_PRIVACY_INTEGRITY_FULL_FIT
      && *main_verf_task_variation_ == verf_variations_t::FRBV) {
    for (int i = 1; i <= temp_iter; ++i) {
      start_training_in_sgx(i);
    }
    // abort();
  } else {
    LOG_ERROR("NOT SUPPORTED\n");
    abort();
  }
#else
#endif
  SET_FINISH_TIMING(SGX_TIMING_OVERALL_TRAINING)

#if 0
  LOG_TRACE("entered in %s\n", __func__)
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  global_training = true;
#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
  bool res = trainer->loadNetworkConfigBlocked();
  LOG_DEBUG("blocked network config file loaded\n")
#ifdef DO_BLOCK_INPUT
  trainer->loadTrainDataBlocked(plain_ds_2d_x, plain_ds_2d_y);
#endif
  trainer->trainBlocked();
#else

  bool res = trainer->loadNetworkConfig();
  LOG_DEBUG("network config file loaded\n");
  trainer->train();
#endif
#else

#endif
  LOG_TRACE("finished in %s\n", __func__);
}

void
ecall_start_predicting() {
  LOG_ERROR("Unimplemented\n");
  abort();
  LOG_TRACE("entered in %s\n", __func__)
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  // bool res = trainer->loadNetworkConfig();
  LOG_INFO("network config file loaded\n")
  // trainer->loadWeights();
  LOG_INFO("weights loaded\n")
  // trainer->predict();
  LOG_INFO("predictions Done!\n")
  LOG_TRACE("finished in %s\n", __func__)
}

#define TILE_M 4   // 4 ops
#define TILE_N 16  // AVX2 = 2 ops * 8 floats
#define TILE_K 16  // loop
#ifdef __cplusplus
#define PUT_IN_REGISTER
#else
#define PUT_IN_REGISTER register
#endif