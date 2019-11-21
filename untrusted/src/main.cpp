#include "CLI/CLI.hpp"
#include "app.h"

extern data_params                        tr_pub_params;
extern std::vector<trainRecordSerialized> plain_dataset;
extern std::vector<trainRecordEncrypted>  encrypted_dataset;

extern data_params                        test_pub_params;
extern std::vector<trainRecordSerialized> plain_test_dataset;
extern std::vector<trainRecordEncrypted>  encrypted_test_dataset;

extern data_params                           predict_pub_params;
extern std::vector<trainRecordSerialized>    plain_predict_dataset;
extern std::vector<trainRecordEncrypted>     encrypted_predict_dataset;
extern sgx::untrusted::CryptoEngine<uint8_t> crypto_engine;

/* Application entry */
int SGX_CDECL
main(int argc, char *argv[]) {
  // (void)(argc);
  // (void)(argv);

  CLI::App arg_parser;
  arg_parser.description("\nSGXADL provides Accountability to Deep Learning\n");

  bool        old_version = false;
  std::string old_json_conf_file("");
  std::string location_conf_file("");
  auto        old_option = arg_parser.add_option_group("OLD", "old way");

  auto task_json_conf
      = old_option
            ->add_option(
                "--task", old_json_conf_file, "json file to describe the task")
            ->check(CLI::ExistingFile)
            ->required();

  auto old_arg
      = old_option
            ->add_flag("--old", old_version, "if you want to do it the old way")
            ->required();
  // task_json_conf->needs(old_arg);

  auto new_option = arg_parser.add_option_group("NEW", "new way");
  new_option->excludes(old_option);

  auto loc_conf_arg
      = new_option
            ->add_option(
                "--loc",
                location_conf_file,
                "give the location of the binary config file for the task")
            ->check(CLI::ExistingFile)
            ->required();
  std::string task_type;
  new_option
      ->add_set("--tasktype",
                task_type,
                {"train", "predict"},
                "choose between train and predict")
      ->required();
  arg_parser.require_option(1, 1);
  CLI11_PARSE(arg_parser, argc, argv);

  if (initialize_enclave() < 0) {
    LOG_ERROR("Something went wrong. Enter a character before exit ...\n");
    getchar();
    return -1;
  }
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (old_version) {
    LOG_DEBUG("Running in old version\n")
    run_config = process_json_config(old_json_conf_file);
    initialize_data(tr_pub_params,
                    test_pub_params,
                    predict_pub_params,
                    plain_dataset,
                    encrypted_dataset,
                    plain_test_dataset,
                    encrypted_test_dataset,
                    plain_predict_dataset,
                    encrypted_predict_dataset,
                    crypto_engine);

    LOG_INFO(
        "Size of plain data is: %fMB\n",
        (double)(plain_dataset.size() * sizeof(plain_dataset[0])) / (1 << 20));

    LOG_INFO("Size of encrypted data is: %fMB\n",
             (double)(encrypted_dataset.size() * sizeof(encrypted_dataset[0]))
                 / (1 << 20));

    ret = ecall_enclave_init(global_eid,
                             (unsigned char *)(&run_config.common_config),
                             sizeof(run_config.common_config));
    CHECK_SGX_SUCCESS(ret, "ecall init enclave caused problem!\n")

    if (run_config.common_config.task == DNNTaskType::TASK_TRAIN_SGX) {
      LOG_DEBUG("starting the training...\n");
      ret = ecall_start_training(global_eid);
      if (ret != SGX_SUCCESS) {
        LOG_ERROR("ecall start training caused problem! Error code is %#010X\n",
                  ret);
        abort();
      }
      LOG_DEBUG("finished the training\n");
    } else if (run_config.common_config.task
               == DNNTaskType::TASK_TRAIN_GPU_VERIFY_SGX) {
      LOG_ERROR("Verify train SGX not implemented\n");
      abort();
    } else if (run_config.common_config.task == DNNTaskType::TASK_TEST_SGX) {
      LOG_ERROR("TEST NOT IMPLEMENTED\n");
      abort();
    } else if (run_config.common_config.task
               == DNNTaskType::TASK_TEST_GPU_VERIFY_SGX) {
      LOG_ERROR("Verify test SGX not implemented\n");
      abort();
    } else if (run_config.common_config.task == DNNTaskType::TASK_INFER_SGX) {
      LOG_DEBUG("starting the prediction...\n");
      ret = ecall_start_predicting(global_eid);
      if (ret != SGX_SUCCESS) {
        LOG_ERROR(
            "ecall start predicting caused problem! Error code is %#010X\n",
            ret);
        abort();
      }
    } else if (run_config.common_config.task
               == DNNTaskType::TASK_INFER_GPU_VERIFY_SGX) {
      LOG_ERROR("Verify predict SGX not implemented\n");
      abort();
    }
  }

  else {
    LOG_DEBUG("Running in new version, \n  location_conf = %s\n  task_type= %s\n",
              location_conf_file.c_str(),
              task_type.c_str())

    #if defined(GPU) && defined(SGX_VERIFIES)
    prepare_enclave(location_conf_file, task_type);
    //prepare_gpu();
    #endif
    
    
  }
  // load_data_set_temp();

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

  // if (task.compare(std::string("train")) == 0) {

  /* Destroy the enclave */
  dest_enclave(global_eid);
// sgx_destroy_enclave(global_eid);
#ifdef MEASURE_SWITCHLESS_TIMING
  print_switchless_timing();
#endif
  print_timers();
  return 0;
}