#include "enclave-app.h"
#include "DNNTrainer.h"
#include "darknet-addons.h"
#include "enclave_t.h"
#include "util.h"
#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
#include <BlockEngine.hpp>
#endif
#include "Channel/BasicChannel.hpp"
#include "Channel/IChannel.hpp"
#include "ipp/ippcp.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <set>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <string>
#include <tuple>
#include <unordered_map>
#include "hexString.h"
#include "rand/PRNG.h"
#include "x86intrin.h"
#include "immintrin.h"
#include "prepare-dnnl.h"

//#include <x86intrin.h>

//#include "/home/aref/projects/libxsmm/include/libxsmm_source.h"
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

namespace sgt = ::sgx::trusted;
/* sgt::darknet::DNNTrainer
    trainer("/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg",
            "", "");
 */
/* sgt::darknet::DNNTrainer
    trainer("/home/aref/projects/SGX-ADL/test/config/imagenet_sample/vgg-16.cfg",
            "", ""); */

//sgt::darknet::DNNTrainer *trainer         = nullptr;
bool                      global_training = true;

int             gpu_index       = -1;
CommonRunConfig comm_run_config = {};

sgx_aes_gcm_128bit_key_t enclave_ases_gcm_key;
sgx_cmac_128bit_key_t    enclave_cmac_key;
sgx_aes_gcm_128bit_key_t client_ases_gcm_key;
sgx_ec256_public_t       enclave_sig_pk_key;
sgx_ec256_private_t      enclave_sig_sk_key;
sgx_ec256_public_t       client_sig_pk_key;

uint64_t session_id;
uint32_t plain_dataset_size;
uint32_t integrity_set_dataset_size;
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
std::unique_ptr<net_context_variations> net_context_ = nullptr;

//std::unique_ptr<verf_variations_t>  verf_scheme_ptr      = nullptr;
std::shared_ptr<network> network_ = nullptr;
std::shared_ptr<network> verf_network_ = nullptr;
std::unique_ptr<verf_variations_t> main_verf_task_variation_;
moodycamel::ConcurrentQueue<verf_task_t> task_queue;

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING)
static std::shared_ptr<sgt::BlockedBuffer<float, 2>> plain_ds_2d_x;
static std::shared_ptr<sgt::BlockedBuffer<float, 2>> plain_ds_2d_y;
static std::shared_ptr<sgt::BlockedBuffer<float, 1>> plain_ds_1d_x;
static std::shared_ptr<sgt::BlockedBuffer<float, 1>> plain_ds_1d_y;
#endif

int total_items = 0;
int single_len_x = 0;
int single_leb_y = 0;



template <typename T>
T swap_endian(T u)
{
    static_assert (CHAR_BIT == 8, "CHAR_BIT != 8");

    union
    {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}


int printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
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
static int checkStatus(const char *funcName, IppStatus expectedStatus,
                       IppStatus status) {
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
  //simple_dnnl_mult();
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
ecall_send_signed_task_config_verify(uint8_t *task_conf, size_t task_conf_len,int verf_type) {
  auto task_config_w_sig = flatbuffers::GetMutableRoot<SignedECC>(task_conf);
  if (verf_type == (int)verf_variations_t::FRBV ) {
    main_verf_task_variation_ = std::unique_ptr<verf_variations_t>(
      new verf_variations_t(verf_variations_t::FRBV));
  }
  else if (verf_type == (int)verf_variations_t::FRBRMMV) {
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
  LOG_DEBUG("arch config len is: %u bytes\n",arch_conf_len)
  // create net_conf_object
  archconfigs.vecBuff = std::vector<uint8_t>(arch_conf_len,0);
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

void ecall_setup_channel(uint64_t chan_id, int channel_type) {
  #if 0
  if (channel_type == ChannelType::TwoWay) {
    BasicChannel<ChannelType::TwoWay>::AddNewChannelToRegistery(
        std::unique_ptr<BasicChannel<ChannelType::TwoWay>>(
            new BasicChannel<ChannelType::TwoWay>(chan_id)));
  } else if (channel_type == ChannelType::OneWayReceiver) {
    BasicChannel<ChannelType::OneWayReceiver>::AddNewChannelToRegistery(
        std::unique_ptr<BasicChannel<ChannelType::OneWayReceiver>>(
            new BasicChannel<ChannelType::OneWayReceiver>(chan_id)));
  } else if (channel_type == ChannelType::OneWaySender) {
    BasicChannel<ChannelType::OneWaySender>::AddNewChannelToRegistery(
        std::unique_ptr<BasicChannel<ChannelType::OneWaySender>>(
            new BasicChannel<ChannelType::OneWaySender>(chan_id)));
  }
  #endif
}

void ecall_tearup_channel(uint64_t chan_id) {}

void ecall_send_to_channel(uint64_t chan_id, unsigned char *buff, size_t len) {
  LOG_DEBUG("Channel %u received a buffer with %u bytes from outised!\n",
            chan_id, len);
}

void ecall_receive_from_channel(uint64_t chan_id, unsigned char *buff,
                                size_t len) {
  LOG_DEBUG("Channel %u is about to send a buffer with %u bytes to outside!\n",
            chan_id, len);
}

/*
This test function tries to encrypt a big buffer of size complete_len bytes
 */
void ecall_test_long_buffer_encrypt(size_t complete_len) {
  if (complete_len % sizeof(float) != 0) {
    LOG_ERROR("complete_len must be divisible by size of float\n")
    abort();
  }
  float current = 0.0;
  float sum = 0.0;
  const size_t buffersize = SGX_OCALL_TRANSFER_BLOCK_SIZE;
  IppStatus status = ippStsNoErr;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  IppsAES_GCMState *pAES = 0;
  int ctxSize = 0;
  uint8_t key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t iv[AES_GCM_IV_SIZE];
  uint8_t mac[AES_GCM_TAG_SIZE];

  status = ippsAES_GCMGetSize(&ctxSize);
  if (!checkStatus("ippsAES_GCMGetSize", ippStsNoErr, status)) {
    abort();
  }
  pAES = (IppsAES_GCMState *)(new Ipp8u[ctxSize]);
  if (NULL == pAES) {
    LOG_ERROR("ERROR: Cannot allocate memory (%d bytes) for AES context\n",
              ctxSize);
    abort();
  }
  status = ippsAES_GCMInit(key, AES_GCM_KEY_SIZE, pAES, ctxSize);
  if (!checkStatus("ippsAES_GCMInit", ippStsNoErr, status)) {
    abort();
  }
  ret = sgx_read_rand(iv, AES_GCM_IV_SIZE);
  CHECK_SGX_SUCCESS(ret, "could not get random iv\n")
  status = ippsAES_GCMStart(iv, AES_GCM_IV_SIZE, NULL, 0, pAES);
  if (!checkStatus("ippsAES_GCMStart", ippStsNoErr, status)) {
    abort();
  }
  size_t q = complete_len / buffersize;
  size_t r = complete_len % buffersize;

  std::vector<float> nums(buffersize / sizeof(float));
  std::vector<uint8_t> enc_nums(buffersize);
  int first = 1;
  for (size_t i = 0; i < q; ++i) {
    for (size_t j = 0; j < nums.size(); ++j) {
      nums[j] = current;
      sum += current;
      current += 0.0000000001;
    }
    status = ippsAES_GCMEncrypt((const uint8_t *)&nums[0],
                                (uint8_t *)&enc_nums[0], buffersize, pAES);
    if (!checkStatus("ippsAES_GCMEncrypt", ippStsNoErr, status)) {
      abort();
    }
    if (first) {
      // ocall with mac
      ret = ocall_test_long_buffer_encrypt_store(
          1, 0, complete_len, &enc_nums[0], buffersize, iv, NULL);
      CHECK_SGX_SUCCESS(ret, "sending encrypted buffer caused problem")
      first = 0;
    } else {
      ret = ocall_test_long_buffer_encrypt_store(
          0, 0, complete_len, &enc_nums[0], buffersize, NULL, NULL);
      CHECK_SGX_SUCCESS(ret, "sending encrypted buffer caused problem")
    }
  }

  if (r > 0) {
    for (size_t j = 0; j < r / sizeof(float); ++j) {
      nums[j] = current;
      sum += current;
      current += 0.0000000001;
    }
    status = ippsAES_GCMEncrypt((const uint8_t *)&nums[0],
                                (uint8_t *)&enc_nums[0], r, pAES);
    if (!checkStatus("ippsAES_GCMEncrypt", ippStsNoErr, status)) {
      abort();
    }
    if (first) {
      // ocall with mac
      ret = ocall_test_long_buffer_encrypt_store(1, 0, complete_len,
                                                 &enc_nums[0], r, iv, NULL);
      CHECK_SGX_SUCCESS(ret, "sending encrypted buffer caused problem")
      first = 0;
    } else {
      ret = ocall_test_long_buffer_encrypt_store(0, 0, complete_len,
                                                 &enc_nums[0], r, NULL, NULL);
      CHECK_SGX_SUCCESS(ret, "sending encrypted buffer caused problem")
    }
  }

  // write mac
  status = ippsAES_GCMGetTag(mac, AES_GCM_TAG_SIZE, pAES);
  if (!checkStatus("ippsAES_GCMGetTag", ippStsNoErr, status)) {
    abort();
  }
  ret = ocall_test_long_buffer_encrypt_store(0, 1, complete_len, NULL, 0, NULL,
                                             mac);
  CHECK_SGX_SUCCESS(ret, "sending tag buffer caused problem")
  LOG_DEBUG("The sum for encryoted floats is: %f\n", sum);
  memset(pAES, 0, ctxSize);
  delete[] pAES;
}

void ecall_test_long_buffer_decrypt(size_t complete_len) {
  if (complete_len % sizeof(float) != 0) {
    LOG_ERROR("complete_len must be divisible by size of float\n")
    abort();
  }
  float sum = 0.0;
  const size_t buffersize = SGX_OCALL_TRANSFER_BLOCK_SIZE;
  IppStatus status = ippStsNoErr;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  IppsAES_GCMState *pAES = 0;
  int ctxSize = 0;
  uint8_t key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t iv[AES_GCM_IV_SIZE];
  uint8_t mac[AES_GCM_TAG_SIZE];
  uint8_t processed_mac[AES_GCM_TAG_SIZE];

  status = ippsAES_GCMGetSize(&ctxSize);
  if (!checkStatus("ippsAES_GCMGetSize", ippStsNoErr, status)) {
    abort();
  }
  pAES = (IppsAES_GCMState *)(new Ipp8u[ctxSize]);
  if (NULL == pAES) {
    LOG_ERROR("ERROR: Cannot allocate memory (%d bytes) for AES context\n",
              ctxSize);
    abort();
  }
  status = ippsAES_GCMInit(key, AES_GCM_KEY_SIZE, pAES, ctxSize);
  if (!checkStatus("ippsAES_GCMInit", ippStsNoErr, status)) {
    abort();
  }

  ret = ocall_test_long_buffer_decrypt_retrieve(1, 0, NULL, 0, iv, mac);
  CHECK_SGX_SUCCESS(ret, "retrieve caused problem\n")
  status = ippsAES_GCMStart(iv, AES_GCM_IV_SIZE, NULL, 0, pAES);
  if (!checkStatus("ippsAES_GCMStart", ippStsNoErr, status)) {
    abort();
  }
  size_t q = complete_len / buffersize;
  size_t r = complete_len % buffersize;

  std::vector<float> nums(buffersize / sizeof(float));
  std::vector<uint8_t> enc_nums(buffersize);

  for (size_t i = 0; i < q; ++i) {
    ret = ocall_test_long_buffer_decrypt_retrieve(
        0, i * buffersize, &enc_nums[0], buffersize, NULL, NULL);
    CHECK_SGX_SUCCESS(ret, "retrieve caused problem\n")
    status = ippsAES_GCMDecrypt((const uint8_t *)&enc_nums[0],
                                (uint8_t *)&nums[0], buffersize, pAES);
    if (!checkStatus("ippsAES_GCMDecrypt", ippStsNoErr, status)) {
      abort();
    }
    for (size_t j = 0; j < nums.size(); ++j) {
      sum += nums[j];
    }
  }

  if (r > 0) {
    ret = ocall_test_long_buffer_decrypt_retrieve(0, q * buffersize,
                                                  &enc_nums[0], r, NULL, NULL);
    CHECK_SGX_SUCCESS(ret, "retrieve caused problem\n")
    status = ippsAES_GCMDecrypt((const uint8_t *)&enc_nums[0],
                                (uint8_t *)&nums[0], r, pAES);
    if (!checkStatus("ippsAES_GCMDecrypt", ippStsNoErr, status)) {
      abort();
    }
    for (size_t j = 0; j < r / sizeof(float); ++j) {
      sum += nums[j];
    }
  }

  // check mac
  status = ippsAES_GCMGetTag(processed_mac, AES_GCM_TAG_SIZE, pAES);
  if (!checkStatus("ippsAES_GCMGetTag", ippStsNoErr, status)) {
    abort();
  }
  if (std::memcmp(mac, processed_mac, AES_GCM_TAG_SIZE) != 0) {
    LOG_ERROR("Computed Tag and provided Tag do not match\n")
    abort();
  }
  LOG_DEBUG("The sum for decrypted floats is: %f\n", sum);
  memset(pAES, 0, ctxSize);
  delete[] pAES;
}

void ecall_enclave_init(unsigned char *common_run_config, size_t len) {
  LOG_TRACE("entered enclave_init!\n");
  LOG_ERROR("DNNTrainer is not included in the build\n");
  abort();
  #if 0
  if (len != sizeof(CommonRunConfig)) {
    LOG_ERROR("size of common_run_config is not what expected!");
  }
  comm_run_config = *((CommonRunConfig *)common_run_config);

  trainer = new sgt::darknet::DNNTrainer(
      comm_run_config.network_arch_file, "", "", comm_run_config.sec_strategy,
      comm_run_config.input_shape.width, comm_run_config.input_shape.height,
      comm_run_config.input_shape.channels,
      comm_run_config.output_shape.num_classes, comm_run_config.train_size,
      comm_run_config.test_size, comm_run_config.predict_size);

  sgx_status_t result = SGX_ERROR_UNEXPECTED;
  uint64_t seed1;
  result = sgx_read_rand((unsigned char *)&seed1, 8);
  if (result != SGX_SUCCESS) {
    LOG_ERROR("reading random number was not successful! Error code is %#010\n",
              result);
    abort();
  }
  uint64_t seed2;
  result = sgx_read_rand((unsigned char *)&seed2, 8);
  if (result != SGX_SUCCESS) {
    LOG_ERROR("reading random number was not successful! Error code is %#010\n",
              result);
    abort();
  }

  // set_random_seed(seed1, seed2);
  set_random_seed(1, 2);
  #endif
  LOG_TRACE("finished enclave_init!\n");
}

void ecall_init_ptext_imgds_blocking2D(int single_size_x_bytes,
                                       int single_size_y_bytes,
                                       int total_items) {
  LOG_TRACE("entered init ptext image data set blocking\n");

#if defined(USE_SGX) && defined(USE_SGX_BLOCKING) && defined(DO_BLOCK_INPUT)
  LOG_ERROR("This part needs change!\n");
  abort();
  int64_t num_pixels = single_size_x_bytes / sizeof(float);
  int64_t num_labels = single_size_y_bytes / sizeof(float);
  plain_ds_2d_x = sgt::BlockedBuffer<float, 2>::MakeBlockedBuffer(
      {total_items, num_pixels});
  LOG_DEBUG("Blocked buffer for plaintext X instantiated! for %d images with "
            "%d pixels\n",
            total_items, num_pixels);
  plain_ds_2d_y = sgt::BlockedBuffer<float, 2>::MakeBlockedBuffer(
      {total_items, num_labels});
  LOG_DEBUG("Blocked buffer for plaintext Y instantiated! for %d images with "
            "%d labels\n",
            total_items, num_labels);

  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_2d_x, x_valid_range, block_val_x, float)
  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_2d_y, y_valid_range, block_val_y, float)

  const int total_single_size = single_size_x_bytes + single_size_y_bytes;
  unsigned char *buff = new unsigned char[total_single_size];
  float *buff_val = nullptr;

  for (int64_t i = 0; i < total_items; ++i) {
    // LOG_DEBUG("processing image %d\n", i);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ocall_get_ptext_img(i, buff, total_single_size);
    CHECK_SGX_SUCCESS(ret, "ocall get ptext img was not successful\n");
    buff_val = reinterpret_cast<float *>(buff);
    for (int64_t j = 0; j < num_pixels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_2d_x, x_valid_range,
                                          block_val_x, true, current_ind, i, j)
      *(block_val_x + (current_ind) - (x_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished X\n", i);
    buff_val += single_size_x_bytes / sizeof(float);
    for (int64_t j = 0; j < num_labels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_2d_y, y_valid_range,
                                          block_val_y, true, current_ind, i, j)
      *(block_val_y + (current_ind) - (y_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished Y\n", i);
  }
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_2d_x, x_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_2d_y, y_valid_range)

  delete[] buff;
#endif
  LOG_TRACE("finished init ptext image data set blocking\n");
}

void ecall_init_ptext_imgds_blocking1D(int single_size_x_bytes,
                                       int single_size_y_bytes,
                                       int total_items) {

  LOG_ERROR("This part needs change!\n");
  abort();
  /* LOG_TRACE("entered init ptext image data set blocking\n");
  int64_t num_pixels = single_size_x_bytes / sizeof(float);
  int64_t num_labels = single_size_y_bytes / sizeof(float);
  plain_ds_1d_x = sgt::BlockedBuffer<float, 1>::MakeBlockedBuffer(
      {total_items, num_pixels});
  LOG_DEBUG("Blocked buffer for plaintext X instantiated!\n");
  plain_ds_1d_y = sgt::BlockedBuffer<float, 1>::MakeBlockedBuffer(
      {total_items, num_labels});
  LOG_DEBUG("Blocked buffer for plaintext Y instantiated!\n");

  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_1d_x, x_valid_range, block_val_x, float)
  BLOCK_ENGINE_INIT_FOR_LOOP(plain_ds_1d_y, y_valid_range, block_val_y, float)

  const int total_single_size = single_size_x_bytes + single_size_y_bytes;
  unsigned char *buff = new unsigned char[total_single_size];
  float *buff_val = nullptr;

  for (int64_t i = 0; i < total_items; ++i) {
    // LOG_DEBUG("processing image %d\n", i);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ocall_get_ptext_img(i, buff, total_single_size);
    CHECK_SGX_SUCCESS(ret, "ocall get ptext img was not successful\n");
    buff_val = reinterpret_cast<float *>(buff);

    for (int64_t j = 0; j < num_pixels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_1d_x, x_valid_range,
                                          block_val_x, true, current_ind, i, j)
      *(block_val_x + (current_ind) - (x_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished X\n", i);
    buff_val += single_size_x_bytes / sizeof(float);
    for (int64_t j = 0; j < num_labels; ++j) {
      BLOCK_ENGINE_COND_CHECK_FOR_LOOP_2D(plain_ds_1d_y, y_valid_range,
                                          block_val_y, true, current_ind, i, j)
      *(block_val_y + (current_ind) - (y_valid_range.block_requested_ind)) =
          *(buff_val + j);
    }
    // LOG_DEBUG("processing image %d finished Y\n", i);
  }
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_1d_x, x_valid_range)
  BLOCK_ENGINE_LAST_UNLOCK(plain_ds_1d_y, y_valid_range)

  delete[] buff;
  LOG_TRACE("finished init ptext image data set blocking\n"); */
}

void ecall_assign_random_id(unsigned char *tr_records, size_t len) {
  LOG_ERROR("This part needs change!\n");
  abort();
  LOG_TRACE("entered ecall assign random id\n");
  // printf("called with length %d\n", len);

  // trainRecordEncrypted *ptr_records = (trainRecordEncrypted *)tr_records;
  // size_t size = len / sizeof(trainRecordEncrypted);
  // auto &crypto_engine = trainer->getCryptoEngine();

  // for (int i = 0; i < size; ++i) {
  //   std::vector<uint8_t> encData(sizeof(trainRecordSerialized));
  //   std::memcpy(&encData[0], &(ptr_records[i].encData),
  //               sizeof(trainRecordSerialized));
  //   std::array<uint8_t, 12> IV;
  //   std::memcpy(&IV[0], (ptr_records[i].IV), 12);
  //   std::array<uint8_t, 16> MAC;
  //   std::memcpy(&MAC[0], (ptr_records[i].MAC), 16);

  //   auto enc_tuple = std::make_tuple(encData, IV, MAC);
  //   auto decrypted = crypto_engine.decrypt(enc_tuple);
  //   trainRecordSerialized *ptr_record = (trainRecordSerialized
  //   *)&decrypted[0]; ptr_record->shuffleID = (unsigned int)rand();

  //   auto encrypted = crypto_engine.encrypt(decrypted);
  //   encData = std::get<0>(encrypted);
  //   std::memcpy(&(ptr_records[i].encData), &encData[0],
  //               sizeof(trainRecordSerialized));
  //   IV = std::get<1>(encrypted);
  //   std::memcpy(&(ptr_records[i].IV[0]), &IV[0], 12);
  //   MAC = std::get<2>(encrypted);
  //   std::memcpy(&(ptr_records[i].MAC[0]), &MAC[0], 16);

  // std::vector<uint8_t> encDatak(sizeof(trainRecordSerialized));
  // std::memcpy(&encDatak[0], &(ptr_records[i].encData),
  // sizeof(trainRecordSerialized));
  // std::array<uint8_t, 12> IVk;
  // std::memcpy(&IVk[0], &(ptr_records[i].IV[0]) , 12);
  // std::array<uint8_t, 16> MACk;
  // std::memcpy(&MACk[0], &(ptr_records[i].MAC[0]), 16);

  // auto enc_tuplek = std::make_tuple(encDatak, IVk, MACk);
  // auto decryptedk = crypto_engine.decrypt(enc_tuplek);
  // printf("waiting for illegal!\n");

  LOG_TRACE("finished ecall assign random id\n");
  //}
}

void ecall_check_for_sort_correctness() {
  LOG_ERROR("This part needs change!\n");
  abort();
  LOG_TRACE("entered ecall check for sort correctness\n");
  /* auto &crypto_engine = trainer->getCryptoEngine();
  uint32_t total_data = 50000;
  uint32_t shuffle_id = 0;
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t> enc_payload(sizeof(trainRecordEncrypted));
  std::vector<uint8_t> enc_data(sizeof(trainRecordSerialized));
  std::array<uint8_t, 12> IV;
  std::array<uint8_t, 16> MAC;

  for (int ind = 0; ind < total_data; ++ind) {

    res = ocall_get_records_encrypted(1, ind, &enc_payload[0],
                                      sizeof(trainRecordEncrypted));
    if (res != SGX_SUCCESS) {
      printf("ocall get records caused problem! the error is "
             "%#010X \n",
             res);
      abort();
    }
    trainRecordEncrypted *enc_r = (trainRecordEncrypted *)&(enc_payload[0]);
    std::memcpy(&enc_data[0], &(enc_r->encData), sizeof(trainRecordSerialized));
    std::memcpy(&IV[0], (enc_r->IV), AES_GCM_IV_SIZE);
    std::memcpy(&MAC[0], (enc_r->MAC), AES_GCM_TAG_SIZE);

    auto enc_tuple = std::make_tuple(enc_data, IV, MAC);
    auto decrypted = crypto_engine.decrypt(enc_tuple);
    trainRecordSerialized *record = (trainRecordSerialized *)&(decrypted[0]);
    if (record->shuffleID < shuffle_id) {
      printf("Unexpected shuffle value for current record and previous one: "
             "%u vs %u\n");
      abort();
    }
    shuffle_id = record->shuffleID;
  } */
  LOG_TRACE("finished ecall check for sort correctness\n");
}

void simple_dnnl_mult() {
  using namespace dnnl;
  size_t M=10,N=5,K=100;
  std::vector<float> a(M*K,1);
  std::vector<float> b(K*N,2);
  std::vector<float> c(M*N,0);
  LOG_OUT("dnnl_sgemm started\n");
  try {
    dnnl_sgemm('N', 'N', M, N, K, 1.0, a.data(), K, b.data(), N, 1.0, c.data(), N);
  }
  catch (dnnl::error &e) {
    LOG_ERROR("dnnl_sgemm status: %d, msg: %s",e.status,e.message)
    abort();
  }
  LOG_OUT("dnnl_sgemm finished\n");
  abort();
}

void ecall_initial_sort() {

  LOG_ERROR("This part needs change!\n");
  abort();
  LOG_TRACE("entered ecall initial sorrt\n");
  //trainer->intitialSort();
  LOG_TRACE("finished ecall initial sorrt\n");
}

void ecall_start_training() {
#ifdef USE_SGX_LAYERWISE
  LOG_DEBUG("Starting the training\n")
  SET_START_TIMING(SGX_TIMING_OVERALL_TRAINING)
  const int temp_iter = 1;

  if (*net_context_ == net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT
      && *main_verf_task_variation_ == verf_variations_t::FRBV) {
    for (int i = 1; i <= temp_iter; ++i) {
      start_training_verification_frbv(i);
    }
    //abort();
  } else if (*net_context_
                 == net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT
             && *main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
    for (int i = 1; i <= temp_iter; ++i) {
      start_training_verification_frbmmv(i);
    }
    //abort();
  }
  else if (*net_context_ == net_context_variations::TRAINING_PRIVACY_INTEGRITY_LAYERED_FIT) {
      for (int i = 1; i <= temp_iter; ++i) {
        start_training_in_sgx(i);
      }
  }
  SET_FINISH_TIMING(SGX_TIMING_OVERALL_TRAINING)
#endif
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

void ecall_start_predicting() {
  LOG_ERROR("Unimplemented\n");
  abort();
  LOG_TRACE("entered in %s\n", __func__)
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  //bool res = trainer->loadNetworkConfig();
  LOG_INFO("network config file loaded\n")
  //trainer->loadWeights();
  LOG_INFO("weights loaded\n")
  //trainer->predict();
  LOG_INFO("predictions Done!\n")
  LOG_TRACE("finished in %s\n", __func__)
}

#define TILE_M 4 // 4 ops
#define TILE_N 16 // AVX2 = 2 ops * 8 floats
#define TILE_K 16 // loop
#ifdef __cplusplus
#define PUT_IN_REGISTER
#else
#define PUT_IN_REGISTER register
#endif


void gemm_nn_fast(int starterM, int M, int N, int K, float ALPHA,
    float *A, int lda,
    float *B, int ldb,
    float *C, int ldc)
{
    int i;

    for (i = starterM; i < starterM + (((M-starterM) / TILE_M)*TILE_M); i += TILE_M)
    {
        int j, k;
        int i_d, k_d;

        for (k = 0; k < (K / TILE_K)*TILE_K; k += TILE_K)
        {
            for (j = 0; j < (N / TILE_N)*TILE_N; j += TILE_N)
            {
                // L1 - 6 bits tag [11:6] - cache size 32 KB, conflict for each 4 KB
                // L2 - 9 bits tag [14:6] - cache size 256 KB, conflict for each 32 KB
                // L3 - 13 bits tag [18:6] - cache size 8 MB, conflict for each 512 KB

                __m256 result256;
                __m256 a256_0, b256_0;    // AVX
                __m256 a256_1, b256_1;    // AVX
                __m256 a256_2;// , b256_2;    // AVX
                __m256 a256_3;// , b256_3;    // AVX
                __m256 c256_0, c256_1, c256_2, c256_3;
                __m256 c256_4, c256_5, c256_6, c256_7;

                c256_0 = _mm256_loadu_ps(&C[(0 + i)*ldc + (0 + j)]);
                c256_1 = _mm256_loadu_ps(&C[(1 + i)*ldc + (0 + j)]);
                c256_2 = _mm256_loadu_ps(&C[(0 + i)*ldc + (8 + j)]);
                c256_3 = _mm256_loadu_ps(&C[(1 + i)*ldc + (8 + j)]);

                c256_4 = _mm256_loadu_ps(&C[(2 + i)*ldc + (0 + j)]);
                c256_5 = _mm256_loadu_ps(&C[(3 + i)*ldc + (0 + j)]);
                c256_6 = _mm256_loadu_ps(&C[(2 + i)*ldc + (8 + j)]);
                c256_7 = _mm256_loadu_ps(&C[(3 + i)*ldc + (8 + j)]);


                for (k_d = 0; k_d < (TILE_K); ++k_d)
                {
                    a256_0 = _mm256_set1_ps(ALPHA*A[(0 + i)*lda + (k_d + k)]);
                    a256_1 = _mm256_set1_ps(ALPHA*A[(1 + i)*lda + (k_d + k)]);

                    a256_2 = _mm256_set1_ps(ALPHA*A[(2 + i)*lda + (k_d + k)]);
                    a256_3 = _mm256_set1_ps(ALPHA*A[(3 + i)*lda + (k_d + k)]);


                    b256_0 = _mm256_loadu_ps(&B[(k_d + k)*ldb + (0 + j)]);
                    b256_1 = _mm256_loadu_ps(&B[(k_d + k)*ldb + (8 + j)]);

                    // FMA - Intel Haswell (2013), AMD Piledriver (2012)
                    // c256_0 = _mm256_fmadd_ps(a256_0, b256_0, c256_0);
                    // c256_1 = _mm256_fmadd_ps(a256_1, b256_0, c256_1);
                    // c256_2 = _mm256_fmadd_ps(a256_0, b256_1, c256_2);
                    // c256_3 = _mm256_fmadd_ps(a256_1, b256_1, c256_3);

                    // c256_4 = _mm256_fmadd_ps(a256_2, b256_0, c256_4);
                    // c256_5 = _mm256_fmadd_ps(a256_3, b256_0, c256_5);
                    // c256_6 = _mm256_fmadd_ps(a256_2, b256_1, c256_6);
                    // c256_7 = _mm256_fmadd_ps(a256_3, b256_1, c256_7);




                    result256 = _mm256_mul_ps(a256_0, b256_0);
                    c256_0 = _mm256_add_ps(result256, c256_0);

                    result256 = _mm256_mul_ps(a256_1, b256_0);
                    c256_1 = _mm256_add_ps(result256, c256_1);

                    result256 = _mm256_mul_ps(a256_0, b256_1);
                    c256_2 = _mm256_add_ps(result256, c256_2);

                    result256 = _mm256_mul_ps(a256_1, b256_1);
                    c256_3 = _mm256_add_ps(result256, c256_3);


                    result256 = _mm256_mul_ps(a256_2, b256_0);
                    c256_4 = _mm256_add_ps(result256, c256_4);

                    result256 = _mm256_mul_ps(a256_3, b256_0);
                    c256_5 = _mm256_add_ps(result256, c256_5);

                    result256 = _mm256_mul_ps(a256_2, b256_1);
                    c256_6 = _mm256_add_ps(result256, c256_6);

                    result256 = _mm256_mul_ps(a256_3, b256_1);
                    c256_7 = _mm256_add_ps(result256, c256_7);
                }
                _mm256_storeu_ps(&C[(0 + i)*ldc + (0 + j)], c256_0);
                _mm256_storeu_ps(&C[(1 + i)*ldc + (0 + j)], c256_1);
                _mm256_storeu_ps(&C[(0 + i)*ldc + (8 + j)], c256_2);
                _mm256_storeu_ps(&C[(1 + i)*ldc + (8 + j)], c256_3);

                _mm256_storeu_ps(&C[(2 + i)*ldc + (0 + j)], c256_4);
                _mm256_storeu_ps(&C[(3 + i)*ldc + (0 + j)], c256_5);
                _mm256_storeu_ps(&C[(2 + i)*ldc + (8 + j)], c256_6);
                _mm256_storeu_ps(&C[(3 + i)*ldc + (8 + j)], c256_7);
            }

            for (j = (N / TILE_N)*TILE_N; j < N; ++j) {
                for (i_d = i; i_d < (i + TILE_M); ++i_d)
                {
                    for (k_d = k; k_d < (k + TILE_K); ++k_d)
                    {
                        PUT_IN_REGISTER float A_PART = ALPHA*A[i_d*lda + k_d];
                        C[i_d*ldc + j] += A_PART*B[k_d*ldb + j];
                    }
                }
            }
        }

        for (k = (K / TILE_K)*TILE_K; k < K; ++k)
        {
            for (i_d = i; i_d < (i + TILE_M); ++i_d)
            {
                PUT_IN_REGISTER float A_PART = ALPHA*A[i_d*lda + k];
                for (j = 0; j < N; ++j) {
                    C[i_d*ldc + j] += A_PART*B[k*ldb + j];
                }
            }
        }
    }
    for (i = starterM + (((M-starterM) / TILE_M)*TILE_M); i < M; ++i) {
        int j, k;
        for (k = 0; k < K; ++k) {
            PUT_IN_REGISTER float A_PART = ALPHA*A[i*lda + k];
            for (j = 0; j < N; ++j) {
                //LOG_DEBUG("segfault for i=%d,j=%d,k=%d\n",i,j,k)
                C[i*ldc + j] += A_PART*B[k*ldb + j];
            }
        }
    }
}

void ecall_handle_gemm_cpu_first_mult(int thread_num) {
#if defined(USE_SGX) && defined (USE_GEMM_THREADING_SGX)
  if (thread_num < 0 || thread_num >= per_thr_params.size()) {
    LOG_DEBUG("GEMM threading was called with wrong param");
    abort();
  }
  auto& task = per_thr_params[thread_num];
  if (task.second._a.load() != thread_task_status_t::not_started) {
    LOG_DEBUG("GEMM threading was called for the same thread again!!");
  }
  task.second._a.store(thread_task_status_t::in_progress);
  int i, j;
  for (i = task.first.starterM; i < task.first.M; ++i) {
    for (j = task.first.starterN; j < task.first.N; ++j) {
      task.first.C[i * task.first.ldc + j] *= task.first.BETA;
    }
  }
  task.second._a.store(thread_task_status_t::finished);
#endif
}

void ecall_handle_gemm_all(int thread_num) {
  #if defined(USE_SGX) && defined (USE_GEMM_THREADING_SGX)                                        
  if (thread_num < 0 || thread_num >= per_thr_params.size()) {
    LOG_DEBUG("GEMM threading was called with wrong param");
    abort();
  }
  auto& task = per_thr_params[thread_num];
  if (task.second._a.load() != thread_task_status_t::not_started) {
    LOG_DEBUG("GEMM threading was called for the same thread again!!");
  }
  task.second._a.store(thread_task_status_t::in_progress);
  // LOG_DEBUG("task started for thread num: %d, starterM=%d, M=%d, N=%d, K=%d, ALPHA=%f, A=%p, lda=%d, B=%p, ldb=%d, C=%p, ldc=%d\n",
  //           thread_num,
  //           task.first.starterM, task.first.M, task.first.N, task.first.K, 
  //           task.first.ALPHA, task.first.A, task.first.lda, task.first.B, task.first.ldb, task.first.C, task.first.ldc)
  // libxsmm_gemm((const char*)&(task.first.TA), (const char*)&(task.first.TB), 
  //   &(task.first.M), &(task.first.N), &(task.first.K), &(task.first.ALPHA), 
  //   task.first.A,&(task.first.lda), task.first.B, &(task.first.lda), 
  //   &(task.first.BETA), (task.first.C+task.first.starterM), &(task.first.ldc));
  if (!task.first.TA && !task.first.TB) {
    // LOG_DEBUG("+calling gemm_nn for thread %d\n", thread_num)
    // gemm_nn(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    #if 0
    int i, j, k;
    for (i = task.first.starterM; i < task.first.M; ++i) {
      for (k = 0; k < task.first.K; ++k) {
        float A_PART = task.first.ALPHA * task.first.A[i * task.first.lda + k];
        for (j = task.first.starterN; j < task.first.N; ++j) {
          task.first.C[i * task.first.ldc + j] += A_PART * task.first.B[k * task.first.ldb + j];
        }
      }
    }
    #else
    gemm_nn_fast(task.first.starterM, task.first.M, task.first.N, task.first.K, 
      task.first.ALPHA, task.first.A, task.first.lda, task.first.B, task.first.ldb, task.first.C, task.first.ldc);
    #endif
  } else if (task.first.TA && !task.first.TB) {
    // LOG_DEBUG("+calling gemm_tn for thread %d\n", thread_num)
    // gemm_tn(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    int i, j, k;
    for (i = task.first.starterM; i < task.first.M; ++i) {
      for (k = 0; k < task.first.K; ++k) {
        float A_PART = task.first.ALPHA * task.first.A[k * task.first.lda + i];
        for (j = task.first.starterN; j < task.first.N; ++j) {
          task.first.C[i * task.first.ldc + j] += A_PART * task.first.B[k * task.first.ldb + j];
        }
      }
    }
  } else if (!task.first.TA && task.first.TB) {
    // gemm_nt(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    // LOG_DEBUG("+calling gemm_nt for thread %d\n", thread_num)
    int i, j, k;
    for (i = task.first.starterM; i < task.first.M; ++i) {
      for (j = task.first.starterN; j < task.first.N; ++j) {
        float sum = 0;
        for (k = 0; k < task.first.K; ++k) {
          sum += task.first.ALPHA * task.first.A[i * task.first.lda + k] * task.first.B[j * task.first.ldb + k];
        }
        task.first.C[i * task.first.ldc + j] += sum;
      }
    }
  } else {
    // gemm_tt(M, N, K, ALPHA, A, lda, B, ldb, C, ldc);
    // LOG_DEBUG("+calling gemm_tt for thread %d\n", thread_num)
    int i, j, k;
    for (i = task.first.starterM; i < task.first.M; ++i) {
      for (j = task.first.starterN; j < task.first.N; ++j) {
        float sum = 0;
        for (k = 0; k < task.first.K; ++k) {
          sum += task.first.ALPHA * task.first.A[i + k * task.first.lda] * task.first.B[k + j * task.first.ldb];
        }
        task.first.C[i * task.first.ldc + j] += sum;
      }
    }
  }
  // LOG_DEBUG("task finished for thread num: %d, starterM=%d, M=%d, N=%d, K=%d, ALPHA=%f, A=%p, lda=%d, B=%p, ldb=%d, C=%p, ldc=%d\n",
  //           thread_num,
  //           task.first.starterM, task.first.M, task.first.N, task.first.K, 
  //           task.first.ALPHA, task.first.A, task.first.lda, task.first.B, task.first.ldb, task.first.C, task.first.ldc)
  task.second._a.store(thread_task_status_t::finished);
  #endif
}

void ecall_handle_fill_cpu(int thread_num) {
  // #if defined(USE_SGX) && defined (USE_GEMM_THREADING_SGX)
  // if (thread_num < 0 || thread_num >= cpu_same_src_dest_per_thr_params.size()) {
  //   LOG_DEBUG("fill cpu threading was called with wrong param\n");
  //   abort();
  // }
  // auto& task = cpu_same_src_dest_per_thr_params[thread_num];
  // if (task.second._a.load() != thread_task_status_t::not_started) {
  //   LOG_DEBUG("fill cpu threading was called for the same thread again!!\n");
  // }
  // task.second._a.store(thread_task_status_t::in_progress);
  // for(int i = task.first.starterN; i < task.first.N; ++i) {
  //   task.first.X[i*task.first.INCX] = task.first.ALPHA;
  // }
  // task.second._a.store(thread_task_status_t::finished);                                        
  // #endif
}

void ecall_handle_scale_cpu(int thread_num) {
// #if defined(USE_SGX) && defined (USE_GEMM_THREADING_SGX)
// if (thread_num < 0 || thread_num >= cpu_same_src_dest_per_thr_params.size()) {
//     LOG_DEBUG("scale cpu threading was called with wrong param\n");
//     abort();
//   }
//   auto& task = cpu_same_src_dest_per_thr_params[thread_num];
//   if (task.second._a.load() != thread_task_status_t::not_started) {
//     LOG_DEBUG("scale cpu threading was called for the same thread again!!\n");
//   }
//   task.second._a.store(thread_task_status_t::in_progress);
//   for(int i = task.first.starterN; i < task.first.N; ++i) {
//     task.first.X[i*task.first.INCX] *= task.first.ALPHA;
//   }
//   task.second._a.store(thread_task_status_t::finished);                                          
// #endif
}
