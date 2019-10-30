#include "app.h"

extern data_params tr_pub_params;
extern std::vector<trainRecordSerialized> plain_dataset;
extern std::vector<trainRecordEncrypted> encrypted_dataset;

extern data_params test_pub_params;
extern std::vector<trainRecordSerialized> plain_test_dataset;
extern std::vector<trainRecordEncrypted> encrypted_test_dataset;

extern data_params predict_pub_params;
extern std::vector<trainRecordSerialized> plain_predict_dataset;
extern std::vector<trainRecordEncrypted> encrypted_predict_dataset;
extern sgx::untrusted::CryptoEngine<uint8_t> crypto_engine;

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
  (void)(argc);
  (void)(argv);

  if (argc < 2) {
    LOG_ERROR("You need to specify the json config file\n");
    abort();
  }
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  run_config = process_json_config(std::string(argv[1]));

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
  
  if (initialize_enclave() < 0) {
    LOG_ERROR("Something went wrong. Enter a character before exit ...\n");
    getchar();
    return -1;
  }

  //load_data_set_temp();  
  ret = ecall_enclave_init(
      global_eid, (unsigned char*)(&run_config.common_config),sizeof(run_config.common_config));
  CHECK_SGX_SUCCESS(ret,"ecall init enclave caused problem!\n")
  
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


  //if (task.compare(std::string("train")) == 0) {
  if (run_config.common_config.task == DNNTaskType::TASK_TRAIN_SGX) {
    LOG_DEBUG("starting the training...\n");
    ret = ecall_start_training(global_eid);
    if (ret != SGX_SUCCESS) {
      LOG_ERROR("ecall start training caused problem! Error code is %#010X\n",
                ret);
      abort();
    }
      LOG_DEBUG("finished the training\n");
  }else if (run_config.common_config.task == DNNTaskType::TASK_TRAIN_GPU_VERIFY_SGX) {
    LOG_ERROR("Verify train SGX not implemented\n");
    abort();
  } else if (run_config.common_config.task == DNNTaskType::TASK_TEST_SGX) {
    LOG_ERROR("TEST NOT IMPLEMENTED\n");
    abort();
  } else if (run_config.common_config.task == DNNTaskType::TASK_TEST_GPU_VERIFY_SGX) {
    LOG_ERROR("Verify test SGX not implemented\n");
    abort();
  } else if (run_config.common_config.task == DNNTaskType::TASK_INFER_SGX) {
    LOG_DEBUG("starting the prediction...\n");
    ret = ecall_start_predicting(global_eid);
    if (ret != SGX_SUCCESS) {
      LOG_ERROR("ecall start predicting caused problem! Error code is %#010X\n",
                ret);
      abort();
    }
  } else if (run_config.common_config.task == DNNTaskType::TASK_INFER_GPU_VERIFY_SGX) {
    LOG_ERROR("Verify predict SGX not implemented\n");
    abort();
  }

  /* Destroy the enclave */
  dest_enclave(global_eid);
  //sgx_destroy_enclave(global_eid);
  #ifdef MEASURE_SWITCHLESS_TIMING
  print_switchless_timing();
  #endif
  print_timers();
  return 0;
}