#include <algorithm>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <tuple>
#include <utility>
#include <vector>

#include <pwd.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX

#include "CryptoEngine.hpp"
#include "app.h"
#include "enclave_u.h"
#include "sgx_uae_service.h"
#include "sgx_urts.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

sgx::untrusted::CryptoEngine<uint8_t>
    crypto_engine(sgx::untrusted::CryptoEngine<uint8_t>::Key{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});

training_pub_params tr_pub_params;
std::vector<trainRecordSerialized> plain_dataset;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX "
     "driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE,
     "The enclave is signed as product enclave, and can not be created as "
     "debuggable enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void) {
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /* Call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME,((int)1) , &token, &updated,
                           &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    return -1;
  }

  return 0;
}

/* initializing dataset params */
void initialize_training_params_cifar(training_pub_params &param) {
  param.label_path = "/home/aref/projects/SGX-DDL/test/config/cifar10/labels.txt";
  param.train_paths = "/home/aref/projects/SGX-DDL/test/config/cifar10/train.list";
  param.width = 28;
  param.height = 28;
  param.channels = 3;
  param.num_classes = 10;
}

/* OCall functions */
void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

void ocall_load_net_config(const unsigned char *path, size_t path_len,
                           char *config, size_t config_len,
                           unsigned int *real_len, unsigned char *config_iv,
                           unsigned char *config_mac) {

  printf("%s:%d@%s =>  ocall_load_net_config started! for file %s with size %zu\n", __FILE__,
         __LINE__, __func__,
         (char *)path, path_len);
  std::ifstream f((const char *)path, std::ios::in | std::ios::binary);

  if (!f.is_open()) {
    throw std::runtime_error("Could not read network config file!");
  }

  std::vector<uint8_t> config_content{std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>()};
  f.close();

  const auto encrypted = crypto_engine.encrypt(config_content);
  const auto config_content_enc = std::get<0>(encrypted);
  const auto config_content_iv = std::get<1>(encrypted);
  const auto config_content_mac = std::get<2>(encrypted);

  *real_len = config_content_enc.size();
  memcpy(config, config_content_enc.data(), *real_len);
  memcpy(config_iv, config_content_iv.data(), AES_GCM_IV_SIZE);
  memcpy(config_mac, config_content_mac.data(), AES_GCM_TAG_SIZE);

  printf("%s:%d@%s =>  ocall_load_net_config finished successfully for size of %zu bytes!\n", __FILE__,
         __LINE__, __func__,
         *real_len);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
  (void)(argc);
  (void)(argv);

  /* Initialize the enclave */
  if (initialize_enclave() < 0) {
    printf("Something went wrong. Enter a character before exit ...\n");
    getchar();
    return -1;
  }

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  ret = ecall_enclave_init(global_eid);
  if (ret != SGX_SUCCESS) {
    printf("ecall init enclave caused problem!\n");
    abort();
  }

  initialize_training_params_cifar(tr_pub_params);
  load_training_data(tr_pub_params);
  serialize_training_data(tr_pub_params,plain_dataset);

  // sgx::untrusted::CryptoEngine<uint8_t> crypto_engine(
  //     {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
  // std::vector<uint8_t> plain = {1,  2,  3,  4,  5,  6,  7,  8, 9,
  //                               10, 11, 12, 13, 14, 15, 16, 17};
  // auto cipher_pack = crypto_engine.encrypt(plain);
  // decltype(plain) plain2 = crypto_engine.decrypt(cipher_pack);

  // if (std::equal(plain.begin(), plain.end(), plain2.begin())) {
  //   std::cout << "enc-dec success!\n";
  // }

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);
  return 0;
}
