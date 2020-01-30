#pragma once
#include <openssl/sha.h>
#include <memory>
#include <unordered_map>
#include <vector>

typedef struct layer_batch_step_report_snapshot_fbv_t_{
    std::vector<uint8_t> layer_updates_bytes;
    std::vector<uint8_t> layer_updates_sha256;
}layer_batch_step_report_snapshot_fbv_t;

typedef struct network_batch_step_report_snapshot_fbv_t_{
    std::unordered_map<int,layer_batch_step_report_snapshot_fbv_t> net_layers_reports;
    std::vector<uint8_t> net_sha256 ;
    std::vector<uint8_t> auth_net_sha256 ;
}network_batch_step_report_snapshot_fbv_t;

typedef struct train_batch_step_report_snapshot_fbv_t_{
    std::unordered_map<int,network_batch_step_report_snapshot_fbv_t> step_net_reports;
}train_batch_step_report_snapshot_fbv_t;

// randomized matrix multiplication verification

typedef struct layer_batch_step_snapshot_frbmmv_t_{
    std::vector<uint8_t> layer_updates_bytes;
    std::vector<uint8_t> layer_forward_MM_outputs;
    std::vector<uint8_t> layer_backward_MM_prev_delta;
    std::vector<uint8_t> layer_updates_sha256;
    std::vector<uint8_t> layer_MM_out_sha256;
    std::vector<uint8_t> layer_MM_delata_prev_sha256;
} layer_batch_step_snapshot_frbmmv_t;

typedef struct network_batch_step_snapshot_frbmmv_t_{
    std::unordered_map<int,layer_batch_step_snapshot_frbmmv_t> net_layers_reports;
    std::vector<uint8_t> net_sha256 ;
    std::vector<uint8_t> auth_net_sha256 ;
}network_batch_step_snapshot_frbmmv_t;

typedef struct train_batch_step_snapshot_snapshot_frbmmv_t_{
    std::unordered_map<int,network_batch_step_snapshot_frbmmv_t> step_net_reports;
}train_batch_step_snapshot_snapshot_frbmmv_t;


// -- enclave produced snapshots

typedef struct layer_batch_step_snapshot_frbv_t_{
    std::vector<uint8_t> layer_params_updates_bytes;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> layer_cmac_128;
}layer_batch_step_snapshot_frbv_t;

typedef struct network_batch_step_snapshot_frbv_t_{
    std::unordered_map<int,layer_batch_step_snapshot_frbv_t> net_layers_reports;
}network_batch_step_snapshot_frbv_t;

typedef struct train_batch_step_snapshot_snapshot_frbv_t_{
    std::unordered_map<int,network_batch_step_snapshot_frbv_t> step_net_reports;
}train_batch_step_snapshot_snapshot_frbv_t;

// -- enclave produced snapshots