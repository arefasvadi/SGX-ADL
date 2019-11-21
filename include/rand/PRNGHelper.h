#pragma once
#include <array>
#include <memory>

#include "PRNG.h"
#include "common-structures.h"

//          SGX_RANDOMNESS
//              /        \
// PRIVATE_ROOT_SEED    PUBLIC_ROOT_SEED
//            -----------/      \-------
//          /                           \
// WEIGHTS_INIT_SEED    EPOCHS_SEED [ep1,ep2,ep3,...]        
//                          |
//              PER_EPOCH_ITERATION_BLOCK_SEED [ep0_blk0,ep0_blk1,...]
//                         |
//                  BATCH_ITERATION_SEED
//                      /           \
// BATCH_INPUT_SELECTION_SEED     ITERATION_PER_LAYER_SEED [L_0,L_1,...]    
// [input_0,input_1,...]          // usually only crop/dropout have randomness
//                                // so we only need to account for them
// typedef struct PRNGHelper {
  
//   PRNGHelper(PRNGHelper* par):parent(par) {};
  
//   std::array<uint64_t, 16>  init_seed;
//   //https://softwareengineering.stackexchange.com/a/211339
//   PRNGHelper* parent = nullptr;

//   std::unordered_map<uint32_t,std::unique_ptr<PRNGHelper>> childs;
//   //uint32_t                               total_childs;
//   //uint32_t                               last_call;

// } PRNGHelper;


// // this is always the first call to get a seed for weight initialization!
// std::unique_ptr<PRNGHelper>&
// derive_weights_init_seed(std::unique_ptr<PRNGHelper>& pub_init_helper);

// // this would be a second call to get a seed from pub_init_seed for deriving per
// // epoch seed
// std::unique_ptr<PRNGHelper>&
// derive_epochs_init_seed(std::unique_ptr<PRNGHelper>& pub_init_helper, int n);

// // this would be the iteration block number call within epoch
// // epoch iterations are divided into blocks of size ONE_EPOCH_NUM_ITRS_BLCK
// std::unique_ptr<PRNGHelper>&
// derive_epochs_iteration_block_init_seed(
//     std::unique_ptr<PRNGHelper>& epochs_helper, int epoch_num);

// // make sure to correctly derive the it_number within block
// std::unique_ptr<PRNGHelper>&
// derive_iteration_init_seed(std::unique_ptr<PRNGHelper>& ep_it_block_helper,
//                       int                          overall_it_number);

// // the first call to iteration_init_seed
// std::unique_ptr<PRNGHelper>&
// derive_iter_batch_select_seed(std::unique_ptr<PRNGHelper>& it_seed_helper);

// // the second call to iteration_init_seed
// std::unique_ptr<PRNGHelper>&
// derive_iter_layers_seed(std::unique_ptr<PRNGHelper>& it_seed_helper);

// // when some layers require random numbers, like random_crop or drop_out
// std::unique_ptr<PRNGHelper>&
// derive_iter_layers_seed(std::unique_ptr<PRNGHelper>& it_layer_seed_helper, 
//     int layer_request_number);

iteration_seed_t get_iteration_seed(
    const std::array<uint64_t,16>& root_seed,
    const int iteration);