#include "load-image.h"
#include "common.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

bool load_training_data(training_pub_params &par) {

  par.labels = get_labels((char *)par.label_path.c_str());
  par.plist = get_paths((char *)par.train_paths.c_str());
  par.paths = (char **)list_to_array(par.plist);
  par.total_records = par.plist->size;
  par.input_data = {0};

  par.input_data.X =
      load_image_paths(par.paths, par.total_records, par.width, par.height);
  par.input_data.y = load_labels_paths(par.paths, par.total_records, par.labels,
                                       par.num_classes, NULL);

  // TODO remember to delete
  // paths in plist
  // free_list too
  // free network too

  return true;
}

bool serialize_training_data(training_pub_params &par,
                             std::vector<trainRecordSerialized> &out) {
  if (par.height * par.width * par.channels != WIDTH_X_HEIGHT_X_CHAN ||
      par.num_classes != NUM_CLASSES) {
    std::cout << "Problems with image size or labels size!!\n";
    std::exit(1);
    // return false;
  }

  out.resize(par.total_records);
  int cnt = 0;
  for (auto &t_record : out) {
    t_record.shuffleID = 0;
    // fill the labels
    std::memcpy(t_record.label, par.input_data.y.vals[cnt],
                NUM_CLASSES * sizeof(float));
    // fill the data
    std::memcpy(t_record.data , par.input_data.X.vals[cnt],
                WIDTH_X_HEIGHT_X_CHAN * sizeof(float));
    ++cnt;
  };
}
