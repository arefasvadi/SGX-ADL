#pragma once
#include <array>
#include "common-structures.h"

typedef struct iteration_randomness_seed_{
  iteration_seed_t it_seed;
  int iteration_number;
}iteration_randomness_seed;

typedef enum class integrity_set_select_obliv_variations_ {
  NON_OBLIVIOUS          = 0,
  OBLIVIOUS_LEAK_INDICES = 1,
  OBLIVIOUS_NO_LEAK      = 2,
} integrity_set_select_obliv_variations;

typedef struct integrity_set_func_non_obliv_args_ {
  float    ratio;
  uint32_t ds_size;
} integrity_set_func_non_obliv_args;

typedef struct integrity_set_func_obliv_indleak_args_ {
  float    ratio;
  uint32_t ds_size;
} integrity_set_func_obliv_indleak_args;

typedef struct integrity_set_func_ {
  union {
    void (*non_obliv)(const integrity_set_func_non_obliv_args*);
    void (*obliv_indleak)(const integrity_set_func_obliv_indleak_args*);
  } invokable;
  integrity_set_select_obliv_variations type_;
} integrity_set_func;

typedef enum class integ_verf_variations_ {
  FRBV = 0,
  FRBRMMV,
  LVV,
}integ_verf_variations;

typedef enum class net_context_variations_
{
  TRAINING_INTEGRITY_FULL_FIT = 0,
  TRAINING_INTEGRITY_LAYERED_FIT,
  TRAINING_PRIVACY_INTEGRITY_FULL_FIT,
  TRAINING_PRIVACY_INTEGRITY_LAYERED_FIT,
  
  PREDICTION_INTEGRITY_FULL_FIT ,
  PREDICTION_INTEGRITY_LAYERED_FIT,
  PREDICTION_PRIVACY_INTEGRITY_FULL_FIT,
  PREDICTION_PRIVACY_INTEGRITY_LAYERED_FIT,
} net_context_variations;

typedef struct net_init_training_integrity_layered_args_ {
  
} net_init_training_integrity_layered_args;

typedef struct net_init_load_net_func_ {
  union {
    void (*init_train_integ_layered)(
        const net_init_training_integrity_layered_args*);
  } invokable;
  net_context_variations net_context;
} net_init_load_net_func;

typedef enum class generic_comp_variations_ {
  ONLY_COMP = 0,
  ONLY_COMP_NO_CHANGE,
  COMP_W_SUB_COMP,
  COMP_W_SUB_COMP_NO_CHANGE,
} generic_comp_variations;

typedef struct comp_id_t_ {
    uint32_t component_id;
} comp_id_t;

typedef struct compsubcomp_id_t_ {
    comp_id_t component_id;
    uint16_t subcomponent_id;
} compsubcomp_id_t;

typedef union comp_or_compsubcomp_id_t_{
    comp_id_t only_component_id;
    compsubcomp_id_t subcomponent_id;
} comp_or_compsubcomp_id_t;

typedef struct additional_auth_data_ {
  uint64_t session_id;
  union {
    struct {
        comp_or_compsubcomp_id_t comp_or_compsubcomp_id;
    } comp_or_subcompcom_no_ts;
    struct {
        comp_or_compsubcomp_id_t comp_or_compsubcomp_id;
        uint32_t time_stamp;
    } comp_or_subcompcom_w_ts;
  } comp_compsubcomp_w_wo_ts;
  generic_comp_variations type_;
} additional_auth_data;
