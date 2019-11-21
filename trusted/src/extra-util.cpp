#include "common.h"
#include "darknet.h"
#include "enclave-app.h"
#include "enclave_t.h"
#include "fbs_gen_code/aes128gcm_generated.h"
#include "fbs_gen_code/cmac128_generated.h"
#include "fbs_gen_code/plainimagelabel_generated.h"
#include "hexString.h"
#include "sgx_trts.h"
#include "util.h"

bool
verify_sha256_single_round(const uint8_t* provided_sha256,
                           const uint8_t* buffer,
                           const size_t   buffer_len,
                           const char*    msg) {
  sgx_sha256_hash_t comp_hash;
  auto              res = sgx_sha256_msg(buffer, buffer_len, &comp_hash);
  CHECK_SGX_SUCCESS(res, "sgx_sha256_msg caused problem!\n")
  const auto comp
      = std::memcmp(comp_hash, provided_sha256, SGX_SHA256_HASH_SIZE);
  LOG_DEBUG(
      "computed hash vs reported hash for %s:\n"
      "\t<\"%s\">\n"
      "\t<\"%s\">\n",
      msg,
      bytesToHexString(comp_hash, SGX_SHA256_HASH_SIZE).c_str(),
      bytesToHexString(provided_sha256, SGX_SHA256_HASH_SIZE).c_str())
  if (comp != 0) {
    LOG_ERROR("Net Config sha256 comparison not accepted!\n")
    return false;
    abort();
  }
  return true;
}

bool
verify_sha256_mult_rounds() {
  return false;
}

void
fix_task_dependent_global_vars() {
  choose_integrity_set.type_
      = integrity_set_select_obliv_variations::OBLIVIOUS_LEAK_INDICES;
  choose_integrity_set.invokable.obliv_indleak
      = choose_rand_integrity_set_nonbliv;

  net_init_loader_ptr
      = std::unique_ptr<net_init_load_net_func>(new net_init_load_net_func);

  verf_scheme_ptr
      = std::unique_ptr<integ_verf_variations>(new integ_verf_variations);
  *verf_scheme_ptr = integ_verf_variations::FRBV;
  if (task_config.objPtr->security_type()
          == EnumSecurityType::EnumSecurityType_integrity
      && task_config.objPtr->task_type()
             == EnumComputationTaskType::EnumComputationTaskType_training) {
#if defined(USE_SGX) && !defined(USE_SGX_LAYERWISE)
    LOG_ERROR("NOT IMPLEMENTED!\n")
    abort();
#endif
    net_init_loader_ptr->net_context
        = net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT;
    net_init_loader_ptr->invokable.init_train_integ_layered
        = init_net_train_integ_layered;

  }

  else if (task_config.objPtr->security_type()
               == EnumSecurityType::EnumSecurityType_integrity
           && task_config.objPtr->task_type()
                  == EnumComputationTaskType::
                      EnumComputationTaskType_prediction) {
    LOG_ERROR("NOT IMPLEMENTED!\n")
    abort();

  } else if (task_config.objPtr->security_type()
                 == EnumSecurityType::EnumSecurityType_privacy_integrity
             && task_config.objPtr->task_type()
                    == EnumComputationTaskType::
                        EnumComputationTaskType_training) {
    LOG_ERROR("NOT IMPLEMENTED!\n")
    abort();
  } else if (task_config.objPtr->security_type()
                 == EnumSecurityType::EnumSecurityType_privacy_integrity
             && task_config.objPtr->task_type()
                    == EnumComputationTaskType::
                        EnumComputationTaskType_prediction) {
    LOG_ERROR("NOT IMPLEMENTED!\n")
    abort();
  }
}

additional_auth_data
construct_aad_input_nochange(uint32_t id) {
  additional_auth_data auth = {};
  auth.session_id           = session_id;
  auth.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_no_ts.comp_or_compsubcomp_id
      .only_component_id.component_id
      = id;
  auth.type_ = generic_comp_variations_::ONLY_COMP;
  return auth;
}

// void
// encrypt_input_sgx_session_key(uint8_t*                    enc_buff,
//                               const uint8_t*              dec_buff,
//                               size_t                      len,
//                               const additional_auth_data* aad,
//                               uint8_t*                    iv,
//                               sgx_aes_gcm_128bit_tag_t*   tag) {
//   sgx_status_t res = SGX_ERROR_UNEXPECTED;
//   auto         iv_ = sgx_root_rng->getRandomLongLong();
//   std::memcpy(iv, &iv_, sizeof(iv_));
//   iv_ = sgx_root_rng->getRandomLongLong();
//   std::memcpy(&iv[sizeof(iv_)], &iv_, SGX_AESGCM_IV_SIZE - sizeof(iv_));
//   res = sgx_rijndael128GCM_encrypt(&enclave_ases_gcm_key,
//                                    dec_buff,
//                                    len,
//                                    enc_buff,
//                                    iv,
//                                    SGX_AESGCM_IV_SIZE,
//                                    (uint8_t*)aad,
//                                    sizeof(*aad),
//                                    tag);
//   CHECK_SGX_SUCCESS(res, "sgx_rijndael128GCM_encrypt caused problem!\n")
//   return;
// }

std::vector<uint8_t>
generate_image_label_flatb_from_actual_bytes(
    const std::vector<uint8_t> in_vec) {
  flatbuffers::FlatBufferBuilder builder(1024);
  std::vector<uint8_t>           flat_out;
  const size_t                   image_content_size
      = dsconfigs.objPtr->img_label_meta()->image_meta()->width()
        * dsconfigs.objPtr->img_label_meta()->image_meta()->height()
        * dsconfigs.objPtr->img_label_meta()->image_meta()->channels();
  const size_t label_content_size
      = dsconfigs.objPtr->img_label_meta()->label_meta()->numClasses();

  auto image
      = builder.CreateVector<float>((float*)&in_vec[0], image_content_size);
  auto labels = builder.CreateVector<float>((float*)&in_vec[image_content_size],
                                            label_content_size);
  PlainImageLabelBuilder pimglbl_builder(builder);
  pimglbl_builder.add_img_content(image);
  pimglbl_builder.add_label_content(labels);

  // auto plainimagelabel = pimglbl_builder.Finish();
  builder.Finish(pimglbl_builder.Finish());
  flat_out.resize(builder.GetSize());
  std::memcpy(flat_out.data(), builder.GetBufferPointer(), builder.GetSize());
  return flat_out;
}

std::vector<uint8_t>
generate_auth_flatbuff(const std::vector<uint8_t>& in_vec,
                       const additional_auth_data* aad,
                       sgx_cmac_state_handle_t*    cmac_handle) {
  flatbuffers::FlatBufferBuilder builder(1024);
  std::vector<uint8_t>           flat_out;
  sgx_cmac_128bit_tag_t          tag;

  auto res = sgx_cmac128_update(in_vec.data(), in_vec.size(), *cmac_handle);
  CHECK_SGX_SUCCESS(res, "sgx_cmac128_update")

  res = sgx_cmac128_update(
      (uint8_t*)aad, sizeof(additional_auth_data), *cmac_handle);
  CHECK_SGX_SUCCESS(res, "sgx_cmac128_update")

  res = sgx_cmac128_final(*cmac_handle, &tag);
  CHECK_SGX_SUCCESS(res, "sgx_cmac128_final")

  auto content  = builder.CreateVector<uint8_t>(in_vec);
  auto aad_auth = builder.CreateVector<uint8_t>((uint8_t*)aad,
                                                sizeof(additional_auth_data));
  auto mac      = builder.CreateVector(tag, sizeof(sgx_cmac_128bit_tag_t));

  CMAC128AuthBuilder cmac_bldr(builder);
  cmac_bldr.add_content(content);
  cmac_bldr.add_aad(aad_auth);
  cmac_bldr.add_mac(mac);

  // auto cmac_auth = cmac_bldr.Finish();
  builder.Finish(cmac_bldr.Finish());

  flat_out.resize(builder.GetSize());
  std::memcpy(flat_out.data(), builder.GetBufferPointer(), builder.GetSize());
  // in vec is already a flatbuffer
  return flat_out;
}

std::vector<uint8_t>
generate_enc_auth_flatbuff(const std::vector<uint8_t>& in_vec,
                           const additional_auth_data* aad) {
  flatbuffers::FlatBufferBuilder builder(1024);

  std::vector<uint8_t>     flat_out;
  std::vector<uint8_t>     enc_buff(in_vec.size(), 0);
  sgx_aes_gcm_128bit_tag_t tag;

  uint8_t iv[AES_GCM_IV_SIZE];

  auto iv_ = sgx_root_rng->getRandomLongLong();
  std::memcpy(iv, &iv_, sizeof(iv_));
  iv_ = sgx_root_rng->getRandomLongLong();
  std::memcpy(&iv[sizeof(iv_)], &iv_, SGX_AESGCM_IV_SIZE - sizeof(iv_));

  auto res = sgx_rijndael128GCM_encrypt(&enclave_ases_gcm_key,
                                        in_vec.data(),
                                        in_vec.size(),
                                        enc_buff.data(),
                                        iv,
                                        SGX_AESGCM_IV_SIZE,
                                        (uint8_t*)aad,
                                        sizeof(*aad),
                                        &tag);
  CHECK_SGX_SUCCESS(res, "sgx_rijndael128GCM_encrypt caused problem!\n")

  auto enc_content = builder.CreateVector(enc_buff);
  auto iv_content  = builder.CreateVector<uint8_t>(iv, AES_GCM_IV_SIZE);
  auto mac_content
      = builder.CreateVector<uint8_t>(tag, sizeof(sgx_aes_gcm_128bit_tag_t));
  auto aad_content = builder.CreateVector<uint8_t>(
      (uint8_t*)aad, sizeof(additional_auth_data));
  AESGCM128EncBuilder aes_bldr(builder);
  aes_bldr.add_enc_content(enc_content);
  aes_bldr.add_iv(iv_content);
  aes_bldr.add_mac(mac_content);
  aes_bldr.add_aad(aad_content);
  builder.Finish(aes_bldr.Finish());
  flat_out.resize(builder.GetSize());
  std::memcpy(flat_out.data(), builder.GetBufferPointer(), builder.GetSize());
  return flat_out;
}

void
set_pub_priv_seeds() {
  std::array<uint64_t, 16> pub_rand_root_seed = {};
  std::array<uint64_t, 16> sgx_rand_root_seed = {};

  auto res = sgx_read_rand((uint8_t*)pub_rand_root_seed.data(),
                           pub_rand_root_seed.size() * sizeof(uint64_t));
  CHECK_SGX_SUCCESS(res, "sgx_read_rand caused problem\n")
  res = sgx_read_rand((uint8_t*)sgx_rand_root_seed.data(),
                      sgx_rand_root_seed.size() * sizeof(uint64_t));
  CHECK_SGX_SUCCESS(res, "sgx_read_rand caused problem\n")

  res = sgx_read_rand((uint8_t*)&session_id, sizeof(session_id));
  CHECK_SGX_SUCCESS(res, "sgx_read_rand caused problem\n")

  sgx_root_rng = std::unique_ptr<PRNG>(new PRNG(sgx_rand_root_seed));
  // TODO: Change this PRNG type to basic array
  pub_root_rng = std::unique_ptr<PRNG>(new PRNG(pub_rand_root_seed));

  // auto hex_root
  //     = bytesToHexString((uint8_t*)pub_rand_root_seed.data(),
  //                        pub_rand_root_seed.size() * sizeof(uint64_t));
  // LOG_DEBUG("enclave is sending pub_root\n<\"%s\">\n", hex_root.c_str())
  // res = ocall_send_pub_root_seed((uint8_t*)pub_rand_root_seed.data(),
  //                                pub_rand_root_seed.size() *
  //                                sizeof(uint64_t));
  // CHECK_SGX_SUCCESS(res, "ocall_send_pub_root_seed caused problem\n")
}

void
choose_rand_integrity_set_nonbliv(
    const integrity_set_func_obliv_indleak_args_* args) {
  if (args->ratio < 0.0f || args->ratio > 1.0f) {
    LOG_ERROR("ratio problem\n")
    abort();
  }
  LOG_DEBUG("started choosing random integrity set\n")
  const auto& DS_SIZE = args->ds_size;
  LOG_WARN(
      "FIXME!\n checking required size is task dependent! preditc does not "
      "require labels in the input stream\n")
  const uint32_t required_buff_size
      = ((dsconfigs.objPtr->img_label_meta()->image_meta()->width()
          * dsconfigs.objPtr->img_label_meta()->image_meta()->height()
          * dsconfigs.objPtr->img_label_meta()->image_meta()->channels())
         + dsconfigs.objPtr->img_label_meta()->label_meta()->numClasses())
        * sizeof(float);
  std::vector<uint8_t> temp_buff(required_buff_size, 0);
  std::vector<uint8_t> temp_buff_dec(required_buff_size, 0);
  LOG_DEBUG("required buff size per image in bytes: %u\n", required_buff_size)

  uint8_t      temp_tag[AES_GCM_TAG_SIZE] = {};
  uint8_t      temp_iv[AES_GCM_IV_SIZE]   = {};
  uint8_t      temp_aad[4]                = {};
  sgx_status_t res                        = SGX_ERROR_UNEXPECTED;

  int chosen_count = 0, not_chosen_count = 0;

  for (uint32_t i = 0; i < DS_SIZE; ++i) {
    // LOG_DEBUG("processing index %u\n",i)
    res = ocall_get_client_enc_image(i,
                                     temp_buff.data(),
                                     required_buff_size,
                                     temp_iv,
                                     AES_GCM_IV_SIZE,
                                     temp_tag,
                                     AES_GCM_TAG_SIZE,
                                     temp_aad,
                                     4);

    CHECK_SGX_SUCCESS(res, "ocall_get_client_enc_image caused problem\n")

    res = sgx_rijndael128GCM_decrypt(&client_ases_gcm_key,
                                     temp_buff.data(),
                                     temp_buff.size(),
                                     temp_buff_dec.data(),
                                     temp_iv,
                                     AES_GCM_IV_SIZE,
                                     temp_aad,
                                     sizeof(4),
                                     &temp_tag);
    CHECK_SGX_SUCCESS(res, "sgx_rijndael128GCM_decrypt caused problem!\n")

    auto chosen = sgx_root_rng->getRandomFloat(0.0, 1.0f) < args->ratio;
    // if chosen, encrypt it with sgx session key
    // otherwise decrypt -- append the necessary info onto the buffer for cmac
    // to verify when pulling back
    sgx_cmac_state_handle_t cmac_handle = nullptr;
    if (chosen) {
      // integ_set_ids.push_back(chosen_count);
      // construct aad
      auto auth = construct_aad_input_nochange(chosen_count);
      // gen flatbuff image and make encrypted flatbuffer
      auto enc_auth_buff = generate_enc_auth_flatbuff(
          generate_image_label_flatb_from_actual_bytes(temp_buff_dec), &auth);

      chosen_count++;
    } else {
      // construct aad
      auto auth = construct_aad_input_nochange(not_chosen_count);
      // generate cmac tag for byte content and image
      res = sgx_cmac128_init(&enclave_cmac_key, &cmac_handle);
      CHECK_SGX_SUCCESS(res, "sgx_cmac128_init caused problem!\n")
      // create flatbuffer for plainimagelabel
      auto auth_buff = generate_auth_flatbuff(
          generate_image_label_flatb_from_actual_bytes(temp_buff_dec),
          &auth,
          &cmac_handle);

      res = sgx_cmac128_close(cmac_handle);
      CHECK_SGX_SUCCESS(res, "sgx_cmac128_close caused problem!\n")

      res = ocall_add_dec_images(auth_buff.data(), auth_buff.size());
      CHECK_SGX_SUCCESS(res, "ocall_add_dec_images caused problem!\n")

      not_chosen_count++;
    }
  }
  LOG_DEBUG("%d chosen as integrity set and %d decrypted\n",
            chosen_count,
            not_chosen_count);
}

void
verify_init_dataset() {
  set_pub_priv_seeds();
  LOG_DEBUG(
      "started verifying the dataset with respect to hash provided in signed "
      "task config\n")
  const auto& DS_SIZE = dsconfigs.objPtr->dataset_size();
  // load inputs one by one, decrypt them with user key, and encrypt them with
  // sgx_session key also, we should select a percentage as i-set (or test-set)
  // in case we are in only-integrity mode
  // keep track of the hash for overall dataset and at last check the sha256
  // has.
  sgx_sha_state_handle_t sha256_handle = nullptr;
  auto                   res           = sgx_sha256_init(&sha256_handle);
  CHECK_SGX_SUCCESS(res, "init sgx_sha256 context caused problem\n")
  const uint32_t required_buff_size
      = ((dsconfigs.objPtr->img_label_meta()->image_meta()->width()
          * dsconfigs.objPtr->img_label_meta()->image_meta()->height()
          * dsconfigs.objPtr->img_label_meta()->image_meta()->channels())
         + dsconfigs.objPtr->img_label_meta()->label_meta()->numClasses())
        * sizeof(float);
  // did not work
  // auto temp_buff = make_unique<uint8_t[]> (required_buff_size);

  // no aad here on the encrypted buffer, it should be added here!
  std::vector<uint8_t> temp_buff(required_buff_size, 0);
  std::vector<uint8_t> temp_buff_dec(required_buff_size, 0);
  LOG_DEBUG("required buff size per image in bytes: %u\n", required_buff_size)

  uint8_t           temp_tag[AES_GCM_TAG_SIZE] = {};
  uint8_t           temp_iv[AES_GCM_IV_SIZE]   = {};
  uint8_t           aad[4]                     = {};
  sgx_sha256_hash_t computed_sha256            = {};
  for (int i = 0; i < DS_SIZE; ++i) {
    res = ocall_get_client_enc_image(i,
                                     temp_buff.data(),
                                     required_buff_size,
                                     temp_iv,
                                     AES_GCM_IV_SIZE,
                                     temp_tag,
                                     AES_GCM_TAG_SIZE,
                                     aad,
                                     4);

    CHECK_SGX_SUCCESS(res, "ocall_get_client_enc_image caused problem\n")

    res = sgx_rijndael128GCM_decrypt(&client_ases_gcm_key,
                                     temp_buff.data(),
                                     temp_buff.size(),
                                     temp_buff_dec.data(),
                                     temp_iv,
                                     AES_GCM_IV_SIZE,
                                     aad,
                                     sizeof(4),
                                     &temp_tag);
    CHECK_SGX_SUCCESS(res, "sgx_rijndael128GCM_decrypt caused problem!\n")

    res = sgx_sha256_update(
        temp_buff_dec.data(), temp_buff_dec.size(), sha256_handle);
    CHECK_SGX_SUCCESS(res, "sgx_sha256_update caused problem!\n")
  }
  res = sgx_sha256_get_hash(sha256_handle, &computed_sha256);
  CHECK_SGX_SUCCESS(res, "sgx_sha256_get_hash caused problem\n")
  res = sgx_sha256_close(sha256_handle);
  CHECK_SGX_SUCCESS(res, "closing sgx_sha256 context caused problem\n")

  int hash_matched
      = std::memcmp(computed_sha256,
                    task_config.objPtr->mutable_dataset_sha256()->Data(),
                    SGX_SHA256_HASH_SIZE);
  auto comp_hex = bytesToHexString(computed_sha256, SGX_SHA256_HASH_SIZE);
  auto rep_hex
      = bytesToHexString(task_config.objPtr->mutable_dataset_sha256()->Data(),
                         SGX_SHA256_HASH_SIZE);
  if (hash_matched == 0) {
    LOG_DEBUG(
        "dataset verified: computed vs reported:\n"
        "\n  <\"%s\">"
        "\n  <\"%s\">\n",
        comp_hex.c_str(),
        rep_hex.c_str());
  } else {
    LOG_ERROR(
        "dataset cannot be verified, computed vs reported:\n"
        "\n  <%s>"
        "\n  <%s>\n",
        comp_hex.c_str(),
        rep_hex.c_str());
    LOG_DEBUG("deletion with success\n")
    abort();
  }
  if (task_config.objPtr->security_type()
      == EnumSecurityType::EnumSecurityType_integrity) {
    // randomly select k_indices and encrypt them if the context is comoutation
    // with integrity
    LOG_WARN(
        "FIXME!\narguments should be set when reading the task config or data "
        "config\n")
    integrity_set_func_obliv_indleak_args indleak_args;
    indleak_args.ratio   = 0.2;
    indleak_args.ds_size = dsconfigs.objPtr->dataset_size();
    choose_integrity_set.invokable.obliv_indleak(&indleak_args);
  } else {
    LOG_DEBUG("Need to connect the routines for privacy_integrity\n")
    abort();
  }
}

// clang-format off
// ocall to load net config

// verify its hash
//
// initialize net config
// depending on the task:
//
// Training
  // a. Privacy + Integrity
  // Everything runs inside enclave and intermediate results are 
  // encrypted/versioned before being sent out.
  // We have both modes for layered or full execution of a network
  // b. Integrity
  // First enclave selects a sample integrity set. This set should be kept
  // private from the untrusted party.
  // In case, the dataset is encrypted, a random selection would suffice based on
  // the freshly generated randomness of enclave. It's OK to leak the ids, but
  // from this point on, all the computation on any element of the integrity-set 
  // is performed obliviously.
  // However, if the dataset is in plaintext (public), it must do it obliviously, 
  // and the selected elements are kept encrypted/authenticated outside.
  
  // When it fits for at least one input image to perform forw/backw/update

  // Enclave loads the network and allocates the necessary buffers! For some
  // networks all buffers
  // inputs/outputs/weights/biases/updates/partial_gradients... can live within
  // the SGX at least for one input batch.

// In Darknet's API, you can do multiple forward/backward and do one weight
// update. There is a division parameter in the network configuration. Sometimes
// even for one GPU it is not feasible to have a batch of 128 images to be
// loaded. for example VGG16 on imagenet. So it is processed in two
// forward/backward passes each for 64 images. Then an update pass will take
// place to change the weights based on the accumulated gradients of previous
// backward passes. As long as the network can be processed with one input in
// enclave, it is better to accumulate the weight updates and do an update when
// batch size is met. In this manner,
// * FRBV setting which computes a full bacth and compares the final weights with
// reported one should be easy to persue.
// * ISAV setting is fine as well since only checks the accuracy and can be
// processed one by one will (not a problem).
// * LVV we need to load the weights/inputs from previous iteration, compute the
// cost. Repeat the same for the reported weights and see if it actually reduced
// the weights. Since we need the cost for a forward pass to compute the loss
// and gradients, we must keep the account of cost for this check and sum them
// to see if it actually reduces.
// * FRBRMMV it's a variation of FRBV, but for matrix multiplications we must have
// the result and the two matrices. Since update phase does not have MM, it only
// considers forward/backward. For MM in fully-connected, the gpu should report
// output rows per enclave batch processing number Input layer to MM is as well
// reported per enclave batch, and it is assumed that weights fit within
// enclave. For conv layers, we should persue a per batch verification any way,
// so it is fine. inputs are weight matrix, and the im2col[or not im2col? again
// we need to check with our computation up until that point] of the input
// filters. We can repeat this twice

// When it does not fit for at least one input image to perform
// forw/backw/update The layered approach is used. So, previous weights are
// loaded, layer by layer and verified with the root hash, then they might go
// out, so must be integrity checked when pulled in for other input bacth or
// backward phase. input and outputs of layers can also be sent out Also, it is
// possible that a single will not fit. This can be the case for Conv layers
// when im2col applied (so they are processed in chunks of channels), or for
// fully connected layers when there us too many weights and weights are
// processed with the granularity of chunks od outputs. GPU must hash them for
// MT with respect to this granularity and integrity /encryption/authentication
// must follow this granularity.

// Enclave sets the initial weights, sends it to GPU. GPU starts computation and
// as soon as computation for a batch (iteration) finishes:
//
//
// Initial Merkle Root hash is computed by enclave
// I. Full Batch Verification  (FRBV)
// GPU will report the root hash of the Merkle Tree for new computed weights and
// sends it to SGX. SGX randomly decides whether it wants to move forward with
// verification of this batch or not. If so, it will be added to a queue for
// verification tasks. In any case, SGX will generate a mac for the reported
// root hash with the iteration number and stores it outside. Those weights are
// kept outside in plaintext with a mac noting the iteration number and root
// hash.
    //                         root_hsh
    //                      /           \
    //                    /              \
    //       hsh(L[1]|L[2]).............hsh(L[N-1]|L[N])
    //       /        \                       /   \
    // hsh(L[1]_ws) hsh(L[2]_ws)....hsh(L[N-1]_ws) hsh(L[N]_ws)
//
// II. Full Batch with Randomized Matrix Multiplication Verification (FRBRMMV)
// In order to perform a faster MM, GPU will also report a Merkle root hash on
// all the inputs and output of the MM ops .
//
// For fully conntected layers:
// this can be divided per batch/and output neurons if it is too big
// forward:   O_(bacth,outputs) = I_(batch,inputs) X TR(W_(outputs,inputs))
// backward:  WU_(outputs,inputs) = TR(delta_(batch,outputs)) X
// net_input(batch,inputs)
//            net_delta(batch,inputs) = delta_(batch,outputs) X
//            W_(outputs,inputs)
//
// For conv layers assume groups is 1
// forward: per batch
// O_(filters,(out_w x out_h)) = 
//      W_(filters,(size x size x channels)) X 
//      I_((size x size x channels),(out_w x out_h)) 
// backward: per batch 
// WU_(filters,(size x size x channels)) =
//    delta_(filters,(out_w x out_h)) X 
//    TR(net_input((size x size x channels),(out_w x out_h)))
// net_delta((size x size x channels),(out_w x out_h)) =
//    TR(w_(filters,(size x size x channels))) X delta_(filters,(out_w x out_h))
// update:
//
// Everytime there is a MM operation such as A_(M,N) = B_(M,K) X C_(K,N) the
// equation will be multiplied by a random vector R_L(1,M) or R_R(N,1) depending
// on the advantage. Without random verification the computation would take O(M
// X N X K) where as in this case it boils down to pereference for check time or
// random generation time becasue they bothe have the same time and space
// complexity if N << M 
// R_L(1,M) X A(M,N) -> Z(1,N) =? V(1,N) <- (R_L(1,M) X B_(M,K)) X C_(K,N)
//      T(N X M)    +         T(N)      +         T(K X M) + T (N X K)
// S(M) + S(N)
// if M << N
// A(M,N) X R_R(N,1) -> Z(M,1) =? V(M,1) <- B_(M,K) X (C_(K,N) X R_R(N,1))
//      T(M X N)   +         T(M)      +         T(M X K) + T (K X N)
// S(N) + S(M)
//                             root_hash
//                          /             \
//                        /                \
// hsh(L[1]_ws) hsh(L[1]_MM_ins_out) ..... hsh(L[N]_ws) hsh(L[N]_MM_ins_out)
//
// III. Loss Value Verification (LVV)
// Whenever GPU submits new weights for an iteration, it is possible to verify
// whether the computation actually lowered the loss with respect to a previous
// weight set if LVV of iteration i is going to be checked, the items in batch i
// will take a forward pass and the loss values are compared between i and i-1
// iterations with previous and new weights. if LVV is chosen against the
// integrity set, the computation should be done privately i.e. inputs/outputs
// enccrypted/authenticated, oblivious computation weights only need to be
// verified for their validity with respect to iteration/reported hash
// IV. Integrity Set Accuracy Verification (ISAV)
// The integrity set is used as the actual test to prevent simple attacks on
// model All the intermediate buffers for inputs/outputs are
// encrypted/authenticated and for this task oblivious mode of computation is
// chosen.

// Prediction
  // SGX only performs prediction for clients if the model was signed by
  // one of the SGX computation networks
  // a. Privacy + Integrity
    // Again as before everything runs in enclave and intermediate
    // inputs/outputs/weights are kept encrypted/authenticated outside
    // Comoutation is done in oblivious mode
  // b. Integrity
    // SGX obliviously chooses a random subset of the data and will keep
    // it encrypted. It will release all the data for verification
    // As in the case for training it can follow with
      // I. Full verification for random selected subset and comparison
      // II. Verification with Randomized MM for other elements in test
        // set.

// clang-format on

void
verify_init_net_config() {
  // verify net conf reported hash
  auto sha256_verify = verify_sha256_single_round(
      task_config.objPtr->mutable_arch_config_sha256()->Data(),
      archconfigs.objPtr->mutable_contents()->Data(),
      archconfigs.objPtr->mutable_contents()->size(),
      "[NET CONFIG]");
  if (!sha256_verify) {
    LOG_ERROR("Net Config sha256 comparison not accepted!\n")
    abort();
  }
  init_net();
}

void
init_net() {
  if (net_init_loader_ptr->net_context
      == net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT) {
    net_init_training_integrity_layered_args args;
    net_init_loader_ptr->invokable.init_train_integ_layered(&args);
  } else {
    LOG_DEBUG("not implemented\n")
  }
}

void
send_batch_seed_to_gpu(const int iteration) {
  auto prng_seeds = get_iteration_seed(pub_root_rng->getState(), iteration);
  auto res        = ocall_gpu_get_iteration_seed(iteration,
                                          (uint8_t*)&prng_seeds.batch_layer_seed[0],
                                          sizeof(uint64_t) * 16,
                                          (uint8_t*)&((prng_seeds.batch_layer_seed)[16]),
                                          sizeof(uint64_t) * 16);
  CHECK_SGX_SUCCESS(res,
                    "sending initial randomness before loading the network")
  // LOG_DEBUG("for batch %d, the generated seeds for PRNGs are sent to gpu:\n"
  //   "1. <" COLORED_STR(RED,"%s") ">\n"
  //   "2. <" COLORED_STR(BRIGHT_GREEN,"%s") ">\n",
  //   iteration,bytesToHexString((uint8_t*)&prng_seeds.batch_layer_seed[0], 
  //     sizeof(uint64_t)*16).c_str(),
  //   bytesToHexString((uint8_t*)&((prng_seeds.batch_layer_seed)[16]), 
  //     sizeof(uint64_t)*16).c_str())
}

// TODO: Be careful if you do threading
void
set_network_batch_randomness(const int iteration,network & net_) {
  auto prng_seeds = get_iteration_seed(pub_root_rng->getState(), iteration);
  // LOG_DEBUG("for batch %d, enclaves PRNGs are :\n"
  //   "1. <" COLORED_STR(RED,"%s") ">\n"
  //   "2. <" COLORED_STR(BRIGHT_GREEN,"%s") ">\n",
  //   iteration,bytesToHexString((uint8_t*)&prng_seeds.batch_layer_seed[0], 
  //     sizeof(uint64_t)*16).c_str(),
  //   bytesToHexString((uint8_t*)&((prng_seeds.batch_layer_seed)[16]), 
  //     sizeof(uint64_t)*16).c_str())
  std::array<uint64_t,16> temp_seed;
  std::memcpy(temp_seed.data(),&prng_seeds.batch_layer_seed[0],sizeof(uint64_t)*16);
  net_.iter_batch_rng      = std::shared_ptr<PRNG>(new PRNG(temp_seed));
  std::memcpy(temp_seed.data(),&((prng_seeds.batch_layer_seed)[16]),sizeof(uint64_t)*16);
  net_.layer_rng_deriver = std::shared_ptr<PRNG>(new PRNG(temp_seed));

  // LOG_DEBUG("inside\nnet_rng iter state : " COLORED_STR(RED,"%s\n") "layer_rng_deriver iter state: " COLORED_STR(BRIGHT_GREEN,"%s\n"),
  // bytesToHexString((const uint8_t*)net_.iter_batch_rng->getState().data(),sizeof(uint64_t)*16).c_str(),bytesToHexString((const uint8_t*)net_.layer_rng_deriver->getState().data(),sizeof(uint64_t)*16).c_str());
}

void
init_net_train_integ_layered(
    const net_init_training_integrity_layered_args* args) {
  (void)args;
  // training
  // integrity checking of gpu's work
  // in FRBV mode
  // layered mode
  send_batch_seed_to_gpu(0);
  // first time should be handled in load_network
  // set_network_bacth_randomness(0);
  auto net_ = load_network(
      (char*)archconfigs.objPtr->mutable_contents()->Data(), nullptr, 1);
  network_ = std::shared_ptr<network>(net_, free_delete());
  LOG_DEBUG(
      "Enclave loaded the network with following values\n"
      "enclave batch size   : %d\n"
      "enclave subdiv size  : %d\n"
      "processings per batch : %d\n",
      network_->batch,
      network_->enclave_subdivisions,
      (network_->batch * network_->enclave_subdivisions))
  // LOG_DEBUG("net_rng iter state : " COLORED_STR(RED,"%s\n") "layer_rng_deriver iter state: " COLORED_STR(BRIGHT_GREEN,"%s\n"),
  // bytesToHexString((const uint8_t*)network_->iter_batch_rng->getState().data(),sizeof(uint64_t)*16).c_str(),bytesToHexString((const uint8_t*)network_->layer_rng_deriver->getState().data(),sizeof(uint64_t)*16).c_str());
  
  // LOG_DEBUG("net_rng iter 0 first int : %d\n",network_->iter_batch_rng->getRandomInt());
  // LOG_DEBUG("layer_rng_deriver iter 0 first int : %d\n",network_->layer_rng_deriver->getRandomInt());
  // LOG_WARN("FIXME!\nnetwork structure and buffers must be managed with care!\n")
}
