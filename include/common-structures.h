#pragma once
#include <memory>

typedef enum SecStrategyType {
  SEC_NOT_MENTIONED = 0,
  SEC_PLAIN = 1,
  SEC_INTEGRITY = 2,
  SEC_PRIVACY = 3,
  SEC_PRIVACY_INTEGRITY = 4,
} SecStrategyType;

typedef enum DNNTaskType {
  TASK_NOT_MENTIONED = 0,
  TASK_TRAIN_SGX = 1,
  TASK_TEST_SGX = 2,
  TASK_INFER_SGX = 3,
  TASK_TRAIN_GPU_VERIFY_SGX = 4,
  TASK_TEST_GPU_VERIFY_SGX = 5,
  TASK_INFER_GPU_VERIFY_SGX = 6,
} DNNTaskType;

typedef struct InputTensorShape {
  int width;
  int height;
  int channels;
} InputTensorShape;

typedef struct OutputTensorShape {
  int num_classes;
  //int num_outputs; // sometimes num_outputs is different from num_classes. ex.
                   // sigmoid layer as the last output layer for binary
                   // classification
} OutputTensorShape;

typedef struct CommonRunConfig {
  char network_arch_file[256];
  InputTensorShape input_shape;
  OutputTensorShape output_shape;
  SecStrategyType sec_strategy;
  DNNTaskType task;
  int train_size;
  int test_size;
  int predict_size;
}CommonRunConfig;

typedef struct RunConfig {
  char train_file_path[256];
  char test_file_path[256];
  char predict_file_path[256];
  char labels_file_path[256];
  char backups_dir_path[256];
  char finalized_weights_file_path[256];
  CommonRunConfig common_config;
  bool is_image;
  bool is_idash;

} RunConfig;

// https://stackoverflow.com/a/3477578/1906041
struct free_delete
{
    void operator()(void* x) { free(x); }
};

typedef struct iteration_seed_t_{
  uint64_t batch_layer_seed[32];
} iteration_seed_t;