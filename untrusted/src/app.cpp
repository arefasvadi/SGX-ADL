#include <algorithm>
#include <assert.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <future>
#include <nlohmann/json.hpp>
#include <pwd.h>
#include <thread>
#include <unistd.h>

#define MAX_PATH FILENAME_MAX

#include "CryptoEngine.hpp"
#include "app.h"
#include "enclave_u.h"
#include "sgx_uae_service.h"
#include "sgx_urts.h"

using json = nlohmann::json;

using timeTracker =
    std::pair<std::chrono::time_point<std::chrono::high_resolution_clock>,
              std::chrono::time_point<std::chrono::high_resolution_clock>>;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

sgx::untrusted::CryptoEngine<uint8_t>
    crypto_engine(sgx::untrusted::CryptoEngine<uint8_t>::Key{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});

data_params tr_pub_params;
std::vector<trainRecordSerialized> plain_dataset;
std::vector<trainRecordEncrypted> encrypted_dataset;

data_params test_pub_params;
std::vector<trainRecordSerialized> plain_test_dataset;
std::vector<trainRecordEncrypted> encrypted_test_dataset;

data_params predict_pub_params;
std::vector<trainRecordSerialized> plain_predict_dataset;
std::vector<trainRecordEncrypted> encrypted_predict_dataset;

std::vector<uint8_t> plain_weights;

std::vector<uint8_t> encrypted_weights;
std::vector<uint8_t> iv_weights;
std::vector<uint8_t> tag_weights;

json configs;

// std::unordered_map<std::string, timeTracker> grand_timer;
std::map<std::string, timeTracker> grand_timer;
std::map<std::string, double> duration_map;

std::unordered_map<uint32_t, std::vector<unsigned char>> layerwise_contents;
std::unordered_map<int64_t, std::vector<unsigned char>> all_blocks;

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
void print_log(const char *str) {
  time_t now = time(0);
  struct tm *ltm = localtime(&now);
  fprintf(stderr, "%s", asctime(ltm));
  fprintf(stderr, "%s\n", str);
}

void main_logger(int level, const char *file, int line, const char *format,
                 ...) {
  char buf[BUFSIZ] = {'\0'};
  char *buf_ptr = buf;
  va_list ap;
  size_t size = 0;
  switch (level) {
  case LOG_TYPE_TRACE:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_CYAN "-------------------------" ANSI_COLOR_RESET
                                    "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_CYAN "[TRACE] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;

    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_CYAN "-------------------------" ANSI_COLOR_RESET
                                    "\n");
    print_log(buf);
    break;
  case LOG_TYPE_DEBUG:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_MAGENTA
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_MAGENTA "[DEBUG] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_MAGENTA
                    "-------------------------" ANSI_COLOR_RESET "\n");
    print_log(buf);
    break;

  case LOG_TYPE_INFO:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_BLUE "-------------------------" ANSI_COLOR_RESET
                                    "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_BLUE "[INFO] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_BLUE "-------------------------" ANSI_COLOR_RESET
                                    "\n");
    print_log(buf);
    break;

  case LOG_TYPE_WARN:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_YELLOW
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size =
        snprintf(buf_ptr, 4096,
                 ANSI_COLOR_YELLOW "[WARNING] -- %s:%d" ANSI_COLOR_RESET "\n",
                 file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_YELLOW
                    "-------------------------" ANSI_COLOR_RESET "\n");
    print_log(buf);
    break;
  case LOG_TYPE_ERROR:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_RED "-------------------------" ANSI_COLOR_RESET
                                   "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_RED "[ERROR] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_RED "-------------------------" ANSI_COLOR_RESET
                                   "\n");
    print_log(buf);
    break;
  case LOG_TYPE_OUT:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_GREEN
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_GREEN "[OUT] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_GREEN
                    "-------------------------" ANSI_COLOR_RESET "\n");
    print_log(buf);
    break;
  default:
    break;
  }
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
  // SGX_DEBUG_FLAG
  ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, &token, &updated, &global_eid,
                           NULL);
  if (ret != SGX_SUCCESS) {
    LOG_ERROR("Error code is %#010X\n", ret);
    return -1;
  }

  return 0;
}

/* OCall functions */
void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

void ocall_print_log(const char *str) { print_log(str); }

void ocall_get_record_sort(int i, unsigned char *tr_record_i, size_t len_i,
                           int j, unsigned char *tr_record_j, size_t len_j) {
  // tr_record_i =(unsigned char*) &encrypted_dataset[i];
  std::memcpy(tr_record_i, &(encrypted_dataset[i]),
              sizeof(trainRecordEncrypted));
  len_i = sizeof(trainRecordEncrypted);

  std::memcpy(tr_record_j, &(encrypted_dataset[j]),
              sizeof(trainRecordEncrypted));
  // tr_record_j =(unsigned char*) &encrypted_dataset[j];
  len_j = sizeof(trainRecordEncrypted);
}

void ocall_get_ptext_img(int loc, unsigned char *buff, size_t len) {
  unsigned char *val_buf =
      reinterpret_cast<unsigned char *>(&plain_dataset[loc].data[0]);
  std::memcpy(buff, val_buf, (plain_dataset[loc].data.size()) * sizeof(float));
  val_buf = reinterpret_cast<unsigned char *>(&plain_dataset[loc].label[0]);
  std::memcpy(buff + (plain_dataset[loc].data.size()) * sizeof(float), val_buf,
              plain_dataset[loc].label.size() * sizeof(float));
}

void ocall_set_record_sort(int i, unsigned char *tr_record_i, size_t len_i,
                           int j, unsigned char *tr_record_j, size_t len_j) {
  LOG_ERROR("This part is not ready yet!\n")
  abort();
  /* trainRecordEncrypted *tr_rec_i = (trainRecordEncrypted *)tr_record_i;
  encrypted_dataset[i] = *tr_rec_i;
  trainRecordEncrypted *tr_rec_j = (trainRecordEncrypted *)tr_record_j;
  encrypted_dataset[j] = *tr_rec_j; */
}

void ocall_get_records_encrypted(int train_or_test, size_t i,
                                 unsigned char *tr_record_i, size_t len_i,
                                 unsigned char *_iv, unsigned char *_tag) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) { // train
    std::memcpy(tr_record_i, &(encrypted_dataset[i].encData[0]), len_i);
    std::memcpy(_iv, (encrypted_dataset[i].IV), AES_GCM_IV_SIZE);
    std::memcpy(_tag, (encrypted_dataset[i].MAC), AES_GCM_TAG_SIZE);
  } else if (train_or_test == 2) {
    std::memcpy(tr_record_i, &(encrypted_test_dataset[i].encData[0]), len_i);
    std::memcpy(_iv, (encrypted_test_dataset[i].IV), AES_GCM_IV_SIZE);
    std::memcpy(_tag, (encrypted_test_dataset[i].MAC), AES_GCM_TAG_SIZE);
  } else if (train_or_test == 3) {
    std::memcpy(tr_record_i, &(encrypted_predict_dataset[i].encData[0]), len_i);
    std::memcpy(_iv, (encrypted_predict_dataset[i].IV), AES_GCM_IV_SIZE);
    std::memcpy(_tag, (encrypted_predict_dataset[i].MAC), AES_GCM_TAG_SIZE);
  }
}

void ocall_set_records_encrypted(int train_or_test, size_t i,
                                 unsigned char *tr_record_i, size_t len_i,
                                 unsigned char *_iv, unsigned char *_tag) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) { // train
    std::memcpy(&(encrypted_dataset[i].encData[0]), tr_record_i, len_i);
    std::memcpy((encrypted_dataset[i].IV), _iv, AES_GCM_IV_SIZE);
    std::memcpy((encrypted_dataset[i].MAC), _tag, AES_GCM_TAG_SIZE);
  } else if (train_or_test == 2) {
    std::memcpy(&(encrypted_test_dataset[i].encData[0]), tr_record_i, len_i);
    std::memcpy((encrypted_test_dataset[i].IV), _iv, AES_GCM_IV_SIZE);
    std::memcpy((encrypted_test_dataset[i].MAC), _tag, AES_GCM_TAG_SIZE);
  } else if (train_or_test == 3) {
    std::memcpy(&(encrypted_predict_dataset[i].encData[0]), tr_record_i, len_i);
    std::memcpy((encrypted_predict_dataset[i].IV), _iv, AES_GCM_IV_SIZE);
    std::memcpy((encrypted_predict_dataset[i].MAC), _tag, AES_GCM_TAG_SIZE);
  }
}

void ocall_get_records_plain(int train_or_test, size_t i,
                             unsigned char *tr_record_i, size_t len_i) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) { // train
    std::memcpy(tr_record_i, &(plain_dataset[i].data[0]),
                sizeof(float) * plain_dataset[i].data.size());
    std::memcpy(tr_record_i + sizeof(float) * plain_dataset[i].data.size(),
                &(plain_dataset[i].label[0]),
                sizeof(float) * plain_dataset[i].label.size());
  } else if (train_or_test == 2) {
    std::memcpy(tr_record_i, &(plain_test_dataset[i].data[0]),
                sizeof(float) * plain_test_dataset[i].data.size());
    std::memcpy(tr_record_i + sizeof(float) * plain_test_dataset[i].data.size(),
                &(plain_test_dataset[i].label[0]),
                sizeof(float) * plain_test_dataset[i].label.size());
  } else if (train_or_test == 3) {
    std::memcpy(tr_record_i, &(plain_predict_dataset[i].data[0]),
                sizeof(float) * plain_predict_dataset[i].data.size());
    std::memcpy(tr_record_i +
                    sizeof(float) * plain_predict_dataset[i].data.size(),
                &(plain_predict_dataset[i].label[0]),
                sizeof(float) * plain_predict_dataset[i].label.size());
  }
}

void ocall_set_records_plain(int train_or_test, size_t i,
                             unsigned char *tr_record_i, size_t len_i) {
  // 1: train
  // 2: test
  // 3: predict
  if (train_or_test == 1) { // train
    std::memcpy(&(plain_dataset[i]), tr_record_i, len_i);
  } else if (train_or_test == 2) {
    std::memcpy(&(plain_test_dataset[i]), tr_record_i, len_i);
  } else if (train_or_test == 3) {
    std::memcpy(&(plain_predict_dataset[i]), tr_record_i, len_i);
  }
}

void ocall_set_timing(const char *time_id, size_t len, int is_it_first_call,
                      int is_it_last_call) {
  timeTracker temp;
  if (grand_timer.find(std::string(time_id)) != grand_timer.end()) {
    if (is_it_first_call == 1) {
      temp.first = std::chrono::high_resolution_clock::now();
      temp.second = std::chrono::high_resolution_clock::now();
      grand_timer[std::string(time_id)] = temp;
    } else {
      temp = grand_timer[std::string(time_id)];
      temp.second = std::chrono::high_resolution_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                         temp.second - temp.first)
                         .count();
      duration_map[std::string(time_id)] += (double)elapsed;
      temp.first = std::chrono::high_resolution_clock::now();
      grand_timer[std::string(time_id)] = temp;
    }
  } else {
    temp.first = std::chrono::high_resolution_clock::now();
    temp.second = std::chrono::high_resolution_clock::now();
    grand_timer[std::string(time_id)] = temp;
    duration_map[std::string(time_id)] = 0.0;
  }
}

void ocall_write_block(int64_t block_id, size_t index, unsigned char *buff,
                       size_t len) {
  std::vector<unsigned char> temp(len, 0);
  std::memcpy(&temp[index], buff, len);
  all_blocks[block_id] = std::move(temp);
}

void ocall_read_block(int64_t block_id, size_t index, unsigned char *buff,
                      size_t len) {
  // std::vector<unsigned char> temp(all_blocks[block_id]);
  std::memcpy(buff, &(all_blocks[block_id][index]), len);
}

void ocall_load_net_config(const unsigned char *path, size_t path_len,
                           char *config, size_t config_len,
                           unsigned int *real_len, unsigned char *config_iv,
                           unsigned char *config_mac) {
  LOG_TRACE("ocall_load_net_config started! for file %s with size %zu\n",
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

  LOG_TRACE("ocall_load_net_config finished successfully for size of "
            "%zu bytes!\n",
            *real_len);
}

void ocall_load_weights_plain(int start, unsigned char *weight_arr,
                              size_t weight_len) {
  static bool first_call = true;
  if (first_call) {
    first_call = false;
    std::string weights_file_str = configs["weights_load_file"];
    plain_weights = read_file_binary(weights_file_str.c_str());
  }
  std::memcpy(weight_arr,&plain_weights[start],weight_len);
}

void ocall_load_weights_encrypted(int start, unsigned char *weight_arr,
                                  size_t weight_len, unsigned char *weights_iv,
                                  unsigned char *weights_mac, int final_round) {
  static bool first_call = true;
  static std::vector<std::string> enc_weight_files_order;
  static std::string enc_weights_file_dir;
  static size_t current_w = 0;
  static std::vector<uint8_t>* curr_enc_weights = nullptr;
  if (first_call) {
    first_call = false;
    enc_weights_file_dir = configs["enc_weights_load_dir"];
    std::string enc_weights_order_file = configs["enc_weights_order_file"];
    enc_weights_order_file = enc_weights_file_dir + enc_weights_order_file;
    enc_weight_files_order = read_file_text(enc_weights_order_file.c_str());
  }
  if (!curr_enc_weights) {
    curr_enc_weights = new std::vector<uint8_t>();
    std::string temp_str = enc_weights_file_dir + enc_weight_files_order[current_w]+std::string(".enc");
    *curr_enc_weights = read_file_binary(temp_str.c_str());
  }
  
  std::memcpy(weight_arr,&((*curr_enc_weights)[start]),weight_len);
  
  if (final_round) {
    std::string temp_str = enc_weights_file_dir + enc_weight_files_order[current_w]+std::string(".iv");
    iv_weights = read_file_binary(temp_str.c_str());
    std::memcpy(weights_iv, &iv_weights[0], AES_GCM_IV_SIZE);
    temp_str = enc_weights_file_dir + enc_weight_files_order[current_w]+std::string(".tag");
    tag_weights = read_file_binary(temp_str.c_str());
    std::memcpy(weights_mac, &tag_weights[0], AES_GCM_TAG_SIZE);
    current_w++;
    delete curr_enc_weights;
    curr_enc_weights = nullptr;
  }
  
}

void ocall_init_buffer_layerwise(uint32_t buff_id, size_t buff_size) {
  /* if (buff_id == 1) {
    auto aaa = 0;
  } */
  layerwise_contents[buff_id] = std::vector<unsigned char>(buff_size, 0);
}

void ocall_get_buffer_layerwise(uint32_t buff_id, uint32_t start, uint32_t end,
                                unsigned char *temp_buff,
                                size_t temp_buff_len) {
  assert((end - start) == temp_buff_len);
  std::memcpy(temp_buff, &((layerwise_contents[buff_id])[start]),
              temp_buff_len);
}

void ocall_set_buffer_layerwise(uint32_t buff_id, uint32_t start, uint32_t end,
                                unsigned char *temp_buff,
                                size_t temp_buff_len) {
  assert((end - start) == temp_buff_len);
  std::memcpy(&((layerwise_contents[buff_id])[start]), temp_buff,
              temp_buff_len);
}

void ocall_handle_gemm_cpu_first_mult(int M, int N, float BETA, int ldc,
                                      size_t address_of_C) {
  #ifdef USE_GEMM_THREADING
  int q = M / AVAIL_THREADS;
  int r = M % AVAIL_THREADS;
  int usable_threads = q == 0 ? 1 : AVAIL_THREADS;
  std::future<sgx_status_t> returns[usable_threads];
  int curr_M = 0;
  for (int i = 0; i < usable_threads; ++i) {
    int M_size = q;
    if (r > 0) {
      M_size += r;
      r = 0;
    }
    returns[i] = std::async(std::launch::async, &ecall_handle_gemm_cpu_first_mult, global_eid,
                            curr_M, curr_M+M_size, N, BETA, ldc, address_of_C);
    curr_M += M_size;
    if (q == 0) {
      break;
    }
  }
  for (int i = 0; i < usable_threads; ++i) {
    auto res = returns[i].get();
    CHECK_SGX_SUCCESS(
        res, "call to ecall_handle_gemm_cpu_first_mult caused problem!!");
  }
  #endif
}

void ocall_handle_gemm_all(int TA, int TB, int M, int N, int K, float ALPHA,
                           size_t addr_A, int lda, size_t addr_B, int ldb,
                           size_t addr_C, int ldc) {
  #ifdef USE_GEMM_THREADING
  int q = M / AVAIL_THREADS;
  int r = M % AVAIL_THREADS;
  int usable_threads = q == 0 ? 1 : AVAIL_THREADS;
  std::future<sgx_status_t> returns[usable_threads];
  int curr_M = 0;
  for (int i = 0; i < usable_threads; ++i) {
    int M_size = q;
    if (r > 0) {
      M_size += r;
      r = 0;
    }
    returns[i] =
        std::async(std::launch::async, &ecall_handle_gemm_all, global_eid, curr_M, TA, TB, curr_M+M_size,
                   N, K, ALPHA, addr_A, lda, addr_B, ldb, addr_C, ldc);
    curr_M += M_size;
    if (q == 0) {
      break;
    }
  }
  for (int i = 0; i < usable_threads; ++i) {
    auto res = returns[i].get();
    CHECK_SGX_SUCCESS(res, "call to ecall_handle_gemm_all caused problem!!");
  }
  #endif
}

void print_timers() {

  for (const auto &s : duration_map) {
    LOG_WARN("++ Item %s took about %f seconds\n", s.first.c_str(),
             s.second / 1000000.0)
  }
}

json process_json_config(const std::string &f_path) {
  std::ifstream json_in(f_path);
  json j;
  json_in >> j;
  return j;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
  (void)(argc);
  (void)(argv);
  if (argc < 2) {
    LOG_ERROR("You need to specify the json config file\n");
    abort();
  }
  configs = process_json_config(std::string(argv[1]));
  LOG_INFO("The loaded config file is:\n%s\n", configs.dump(2).c_str());

  initialize_data(tr_pub_params, test_pub_params, predict_pub_params,
                  plain_dataset, encrypted_dataset, plain_test_dataset,
                  encrypted_test_dataset, plain_predict_dataset,
                  encrypted_predict_dataset, crypto_engine);

  LOG_INFO("Size of plain data is: %fMB\n",
           (double)(plain_dataset.size() * sizeof(plain_dataset[0])) /
               (1 << 20));

  LOG_INFO("Size of encrypted data is: %fMB\n",
           (double)(encrypted_dataset.size() * sizeof(encrypted_dataset[0])) /
               (1 << 20));

  /* Initialize the enclave */
  if (initialize_enclave() < 0) {
    LOG_ERROR("Something went wrong. Enter a character before exit ...\n");
    getchar();
    return -1;
  }

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  std::string network_arch_string = configs["network_config"];
  std::string task = configs["task"];
  std::string sec_mode = configs["security"];
  ret = ecall_enclave_init(
      global_eid, network_arch_string.c_str(), task.c_str(), sec_mode.c_str(),
      configs["data_config"]["dims"][0], configs["data_config"]["dims"][1],
      configs["data_config"]["dims"][2], configs["data_config"]["num_classes"],
      configs["data_config"]["trainSize"], configs["data_config"]["testSize"],
      configs["data_config"]["predictSize"]);
  if (ret != SGX_SUCCESS) {
    LOG_ERROR("ecall init enclave caused problem! Error code is %#010\n", ret);
    abort();
  }

  /* ret = ecall_singal_convolution(global_eid, 20000000, 10000);
  if (ret != SGX_SUCCESS) {
    printf("ecall for signal conv caused problem! Error code is %#010\n", ret);
    abort();
  } */

  /* ret = ecall_matrix_mult(global_eid,1000,1000,1000,1000);
  if (ret != SGX_SUCCESS) {
    printf("ecall for matrix multiplication caused problem! Error code is
  %#010\n", ret); abort();
  } */

  /* ret = ecall_init_ptext_imgds_blocking2D(
      global_eid, sizeof(plain_dataset[0].data), sizeof(plain_dataset[0].label),
      plain_dataset.size());
  CHECK_SGX_SUCCESS(
      ret, "ecall to init plaintext image dataset blocking wa unsuccessful!\n");
*/

  /* random_id_assign(encrypted_dataset);

  ret = ecall_initial_sort(global_eid);
  if (ret != SGX_SUCCESS) {
    LOG_ERROR(
        "ecall initial sort enclave caused problem! Error code is %#010X\n ",
        ret);
    abort();
  }

  LOG_DEBUG("check for sorting started\n");
  ret = ecall_check_for_sort_correctness(global_eid);
  if (ret != SGX_SUCCESS) {
    LOG_ERROR("ecall checking sort correctness caused problem! Error code is "
              "%#010X\n ",
              ret);
    abort();
  }
  LOG_DEBUG("check for sorting finished successfully\n"); */

  if (task.compare(std::string("train")) == 0) {
    LOG_DEBUG("starting the training...\n");
    ret = ecall_start_training(global_eid);
    if (ret != SGX_SUCCESS) {
      LOG_ERROR("ecall start training caused problem! Error code is %#010X\n",
                ret);
      abort();
    }
    LOG_DEBUG("finished the training\n");
  } else if (task.compare(std::string("test")) == 0) {
    LOG_ERROR("TEST NOT IMPLEMENTED\n")
    abort();
  } else if (task.compare(std::string("predict")) == 0) {
    LOG_DEBUG("starting the prediction...\n");
    ret = ecall_start_predicting(global_eid);
    if (ret != SGX_SUCCESS) {
      LOG_ERROR("ecall start predicting caused problem! Error code is %#010X\n",
                ret);
      abort();
    }
  }

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  print_timers();
  return 0;
}
