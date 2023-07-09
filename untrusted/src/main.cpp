#include "CLI/CLI.hpp"
#include "app.h"
#include "common.h"
#include "timingdefs.h"

extern data_params                        tr_pub_params;
extern std::vector<trainRecordSerialized> plain_dataset;
extern std::vector<trainRecordEncrypted>  encrypted_dataset;

extern data_params                        test_pub_params;
extern std::vector<trainRecordSerialized> plain_test_dataset;
extern std::vector<trainRecordEncrypted>  encrypted_test_dataset;

extern data_params                           predict_pub_params;
extern std::vector<trainRecordSerialized>    plain_predict_dataset;
extern std::vector<trainRecordEncrypted>     encrypted_predict_dataset;

/* Application entry */
int SGX_CDECL
main(int argc, char *argv[]) {
  // (void)(argc);
  // (void)(argv);

  SET_START_TIMING(APP_TIMING_OVERALL);
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
  std::string verf_type;
  new_option->add_set("--verftype", 
    verf_type, {"RF","RMM"},
    "choose between randomized w.o randomized MM or w randomized MM")->required();
  arg_parser.require_option(1, 1);
  CLI11_PARSE(arg_parser, argc, argv);

  if (initialize_enclave() < 0) {
    LOG_ERROR("Something went wrong. Enter a character before exit ...\n");
    getchar();
    return -1;
  }
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (old_version) {
    LOG_ERROR("Running in old version which is not supported\n")
    abort();
  }
  else {
    LOG_DEBUG("Running in new version, \n  location_conf = %s\n  task_type= %s\n",
              location_conf_file.c_str(),
              task_type.c_str())

    #if defined(GPU) && defined(SGX_VERIFIES)
    prepare_enclave(location_conf_file, task_type,verf_type);
    //prepare_gpu();
    #endif
  }

  /* Destroy the enclave */
  dest_enclave(global_eid);
#ifdef MEASURE_SWITCHLESS_TIMING
  print_switchless_timing();
#endif
  SET_FINISH_TIMING(APP_TIMING_OVERALL);
  print_timers();
  return 0;
}