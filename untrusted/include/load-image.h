#pragma once

#include "common.h"
#include <vector>

#if defined(__cplusplus)
extern "C" {
#endif

#include "../../third_party/darknet/include/darknet.h"
matrix load_image_paths(char **paths, int n, int w, int h);
matrix load_labels_paths(char **paths, int n, char **labels, int k,
                         tree *hierarchy);

#if defined(__cplusplus)
}
#endif

#include <string>
#undef USE_SGX


typedef struct training_pub_params {
  std::string label_path;
  // std::vector<std::string> labels;
  std::string train_paths;

  int total_records;
  int num_classes;

  int width;
  int height;
  int channels;

  data input_data;
  list *plist;
  char **paths;
  char **labels;

} training_pub_params;

bool load_training_data(training_pub_params &par);
bool serialize_training_data(training_pub_params &par,
                             std::vector<trainRecordSerialized> &out);
