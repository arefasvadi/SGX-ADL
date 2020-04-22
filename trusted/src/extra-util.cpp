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
#include <unordered_set>
#include <queue>

void OCALL_LOAD_LAYER_REPRT_FRBV(int iteration, int layer_index, size_t buff_ind,
                                uint8_t* buff, size_t size_bytes, uint8_t* layer_sha,
                                size_t layer_sha_len) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (buff != nullptr) {
    const size_t interim_buff_len = (64 * ONE_KB);
    int          q                = size_bytes / (interim_buff_len);
    int          r                = size_bytes % (interim_buff_len);
    for (int ii = 0; ii < q; ++ii) {
      ret = ocall_load_layer_report_frbv(iteration,
                                        layer_index,
                                        buff_ind + ii * interim_buff_len,
                                        buff + ii * interim_buff_len,
                                        interim_buff_len,
                                        nullptr,
                                        0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
    }
    if (r != 0) {
      ret = ocall_load_layer_report_frbv(iteration,
                                        layer_index,
                                        buff_ind + interim_buff_len * q,
                                        buff + interim_buff_len * q,
                                        r,
                                        nullptr,
                                        0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
    }
  }
  if (layer_sha != nullptr) {
    ret = ocall_load_layer_report_frbv(iteration,
                                       layer_index,
                                       0,
                                       nullptr,
                                       0,
                                       layer_sha,
                                       layer_sha_len);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
  }
}

void OCALL_LOAD_LAYER_REPRT_FRBMMV(int iteration,int layer_index,
                                  size_t buff_updates_ind,uint8_t* buff_updates,size_t size_bytes_updates,                     
                                  uint8_t* buff_updates_sha,size_t buff_updates_sha_len,
                                  size_t buff_mm_ind,uint8_t* buff_mm,size_t size_bytes_mm,                           
                                  uint8_t* buff_mm_sha,size_t buff_mm_sha_len,                         
                                  size_t buff_prevdelta_ind,uint8_t* buff_prevdelta,size_t size_bytes_prevdelta,                    
                                  uint8_t* buff_prevdelta_sha,size_t buff_prevdelta_sha_len) {                                                                            
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (buff_updates != nullptr) {                                             
    const size_t interim_buff_len = (64 * ONE_KB);                           
    int          q                = size_bytes_updates / (interim_buff_len); 
    int          r                = size_bytes_updates % (interim_buff_len); 
    for (int ii = 0; ii < q; ++ii) {
      ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        buff_updates_ind + ii * interim_buff_len,
                                        buff_updates + ii * interim_buff_len,
                                        interim_buff_len,
                                        nullptr,0,
                                        0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
    }
    if (r != 0) {
      ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        buff_updates_ind + interim_buff_len * q,
                                        buff_updates + interim_buff_len * q,
                                        r,
                                        nullptr,0,
                                        0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
    }
  }                                                                          
  
  if (buff_updates_sha != nullptr) { 
    ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,
                                        nullptr,
                                        0,
                                        buff_updates_sha,buff_updates_sha_len,
                                        0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
  }

  if (buff_mm != nullptr) {
    const size_t interim_buff_len = (64 * ONE_KB);                           
    int          q                = size_bytes_mm / (interim_buff_len); 
    int          r                = size_bytes_mm % (interim_buff_len);
    for (int ii = 0; ii < q; ++ii) {
      ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,
                                        buff_mm_ind+ ii * interim_buff_len, buff_mm+ ii * interim_buff_len, interim_buff_len, 
                                        nullptr, 0, 0, nullptr, 0,nullptr, 0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
    }
    if (r != 0) {
      ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,
                                        buff_mm_ind+ q * interim_buff_len, buff_mm+ q * interim_buff_len, r, 
                                        nullptr, 0, 
                                        0, nullptr, 0,nullptr, 0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
    }
  }

  if (buff_mm_sha != nullptr) {
    ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,
                                        0, nullptr, 0, 
                                        buff_mm_sha, buff_mm_sha_len, 
                                        0, nullptr, 0,nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")    
  }

  if (buff_prevdelta != nullptr) {
    const size_t interim_buff_len = (64 * ONE_KB);                           
    int          q                = size_bytes_prevdelta / (interim_buff_len); 
    int          r                = size_bytes_prevdelta % (interim_buff_len);
    for (int ii = 0; ii < q; ++ii) {
      ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,
                                        0, nullptr, 0, 
                                        nullptr, 0, 
                                        buff_prevdelta_ind+ ii * interim_buff_len, buff_prevdelta+ ii * interim_buff_len, interim_buff_len, 
                                        nullptr, 0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
    }
    if (r != 0) {
      ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,
                                        0, nullptr, 0, 
                                        nullptr, 0, 
                                        buff_prevdelta_ind+ q * interim_buff_len, buff_prevdelta+ q * interim_buff_len, r, 
                                        nullptr, 0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
    }
  }

  if (buff_prevdelta_sha != nullptr) {
    ret = ocall_load_layer_report_frbmmv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,
                                        0, nullptr, 0, 
                                        nullptr, 0, 
                                        0, nullptr, 0,buff_prevdelta_sha, buff_prevdelta_sha_len);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
  }
}

void OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(int iteration,int layer_index, size_t   start, uint8_t *buff,
                                              size_t   buff_len, uint8_t* aad, size_t aad_len,
                                              uint8_t *layer_cmac, size_t   layer_cmac_len) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (buff != nullptr) {
    const size_t interim_buff_len = (64 * ONE_KB);                           
    int          q                = buff_len / (interim_buff_len); 
    int          r                = buff_len % (interim_buff_len); 
    for (int ii = 0; ii < q; ++ii) {
      ret = ocall_save_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        start + ii * interim_buff_len,
                                        buff + ii * interim_buff_len,
                                        interim_buff_len,
                                        nullptr,
                                        0,nullptr,0);
      CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
    }
    if (r != 0) {
      ret = ocall_save_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        start + interim_buff_len * q,
                                        buff + interim_buff_len * q,
                                        r,
                                        nullptr,
                                        0,nullptr,0);
      CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
    }
  }
  if (aad != nullptr) {
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        aad,aad_len,nullptr,0);
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  if (layer_cmac != nullptr) {
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,layer_cmac,layer_cmac_len);
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
}

void OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(int iteration,int layer_index, size_t   start, uint8_t *buff,
                                              size_t   buff_len, uint8_t* aad, size_t aad_len,
                                              uint8_t *layer_cmac, size_t   layer_cmac_len) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (buff != nullptr) {
    const size_t interim_buff_len = (64 * ONE_KB);                           
    int          q                = buff_len / (interim_buff_len); 
    int          r                = buff_len % (interim_buff_len); 
    for (int ii = 0; ii < q; ++ii) {
      ret = ocall_load_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        start + ii * interim_buff_len,
                                        buff + ii * interim_buff_len,
                                        interim_buff_len,
                                        nullptr,
                                        0,nullptr,0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    }
    if (r != 0) {
      ret = ocall_load_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        start + interim_buff_len * q,
                                        buff + interim_buff_len * q,
                                        r,
                                        nullptr,
                                        0,nullptr,0);
      CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    }
  }
  if (aad != nullptr) {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        aad,aad_len,nullptr,0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  if (layer_cmac != nullptr) {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration,
                                        layer_index,
                                        0,nullptr,0,
                                        nullptr,0,layer_cmac,layer_cmac_len);
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
  }
}


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
  if (msg != nullptr) {
    LOG_DEBUG(
      "computed hash vs reported hash for %s:\n"
      "\t<\"%s\">\n"
      "\t<\"%s\">\n",
      msg,
      bytesToHexString(comp_hash, SGX_SHA256_HASH_SIZE).c_str(),
      bytesToHexString(provided_sha256, SGX_SHA256_HASH_SIZE).c_str())
  }
  if (comp != 0) {
    LOG_ERROR("Net Config sha256 comparison not accepted!\n")
    return false;
    abort();
  }
  return true;
}

bool
verify_sha256_mult_rounds(sgx_sha_state_handle_t* sha256_handle,
                          const uint8_t* provided_sha256,
                          const uint8_t* buffer,
                          const size_t   buffer_len,
                          const char*    msg) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (*sha256_handle == nullptr) {
    ret = sgx_sha256_init(sha256_handle);
    CHECK_SGX_SUCCESS(ret, "sgx_sha256_init caused problem\n")
  }
  if (buffer!=nullptr){
    ret = sgx_sha256_update(buffer,buffer_len,*sha256_handle);
    CHECK_SGX_SUCCESS(ret, "sgx_sha256_update caused problem\n")
  }

  if (provided_sha256 != nullptr) {
    // final round
    sgx_sha256_hash_t comp_hash;
    ret = sgx_sha256_get_hash(*sha256_handle, &comp_hash);
    CHECK_SGX_SUCCESS(ret, "sgx_sha256_get_hash caused problem\n")

    const auto comp
        = std::memcmp(comp_hash, provided_sha256, SGX_SHA256_HASH_SIZE);
    if (msg != nullptr) {
      LOG_DEBUG(
          "computed hash vs reported hash for %s:\n"
          "\t<\"%s\">\n"
          "\t<\"%s\">\n",
          msg,
          bytesToHexString(comp_hash, SGX_SHA256_HASH_SIZE).c_str(),
          bytesToHexString(provided_sha256, SGX_SHA256_HASH_SIZE).c_str())
    }
    // close
    ret = sgx_sha256_close(*sha256_handle);
    CHECK_SGX_SUCCESS(ret, "sgx_sha256_close caused problem\n")
    *sha256_handle = nullptr;
    if (comp != 0) {
      LOG_ERROR("sha256 comparison not accepted!\n")
      abort();
      return false;
    }
  }
  return true;
}

bool verify_cmac128_single_round(const uint8_t* msg,const size_t msg_len,
    const uint8_t* tag,const uint8_t* aad,const size_t aad_len) {
  sgx_cmac_state_handle_t cmac_handle;
  sgx_cmac_128bit_tag_t computed_tag;
  auto ret = sgx_cmac128_init(&enclave_cmac_key,&cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_init caused problem\n")
  ret =  sgx_cmac128_update(msg,msg_len,cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_update caused problem\n")
  if (aad != nullptr) {
    ret =  sgx_cmac128_update(aad,aad_len,cmac_handle); 
    CHECK_SGX_SUCCESS(ret, "sgx_cmac128_update caused problem\n")
  }
  ret = sgx_cmac128_final(cmac_handle,&computed_tag);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_final caused problem\n")
  ret = sgx_cmac128_close(cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_close caused problem\n")
  const auto comp
      = std::memcmp(computed_tag, tag, SGX_CMAC_MAC_SIZE);
  if (comp != 0) {
    LOG_ERROR("cmac128 comparison not accepted!\n")
    // abort();
    return false;
  }
  return true;
}

bool
gen_verify_cmac128_multiple_rounds(bool generate,
                               sgx_cmac_state_handle_t* cmac_handle,
                               uint8_t*                 msg,
                               size_t                   msg_len,
                               uint8_t*                 tag,
                               uint8_t*                 aad,
                               size_t                   aad_len) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if (*cmac_handle == nullptr) {
    ret = sgx_cmac128_init(&enclave_cmac_key, cmac_handle);
    CHECK_SGX_SUCCESS(ret, "sgx_cmac128_init caused problem\n")
  }
  if (msg != nullptr) {
    ret = sgx_cmac128_update(msg, msg_len, *cmac_handle);
    CHECK_SGX_SUCCESS(ret, "sgx_cmac128_update caused problem\n")
  }
  if (aad != nullptr) {
    ret = sgx_cmac128_update(aad, aad_len, *cmac_handle);
    CHECK_SGX_SUCCESS(ret, "sgx_cmac128_update caused problem\n")
  }
  if (tag != nullptr) {
    sgx_cmac_128bit_tag_t computed_tag;
    if (generate) {
      ret = sgx_cmac128_final(*cmac_handle, &computed_tag);
      CHECK_SGX_SUCCESS(ret, "sgx_cmac128_final caused problem\n")
      ret = sgx_cmac128_close(*cmac_handle);
      CHECK_SGX_SUCCESS(ret, "sgx_cmac128_close caused problem\n")
      *cmac_handle = nullptr;
      std::memcpy(tag, computed_tag, SGX_CMAC_MAC_SIZE);
    }
    else {
      
      ret = sgx_cmac128_final(*cmac_handle, &computed_tag);
      CHECK_SGX_SUCCESS(ret, "sgx_cmac128_final caused problem\n")
      ret = sgx_cmac128_close(*cmac_handle);
      CHECK_SGX_SUCCESS(ret, "sgx_cmac128_close caused problem\n")
      *cmac_handle = nullptr;
      const auto comp = std::memcmp(computed_tag, tag, SGX_CMAC_MAC_SIZE);
      if (comp != 0) {
        LOG_ERROR("cmac128 comparison not accepted!\n")
        // abort();
        return false;
      }
    }
  }
  return true;
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
      = std::unique_ptr<verf_variations_t>(new verf_variations_t);
  *verf_scheme_ptr = verf_variations_t::FRBV;
  if (task_config.objPtr->security_type()
          == EnumSecurityType::EnumSecurityType_integrity
      && task_config.objPtr->task_type()
             == EnumComputationTaskType::EnumComputationTaskType_training) {
#if defined(USE_SGX) && !defined(USE_SGX_LAYERWISE)
    LOG_ERROR("NOT IMPLEMENTED!\n")
    abort();
#endif
    net_context_ = std::unique_ptr<net_context_variations>(new net_context_variations);
    *net_context_ = net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT;
    net_init_loader_ptr->net_context
        = net_context_.get();
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

additional_auth_data construct_aad_frbv_report_nochange_ts(uint32_t id,uint32_t ts) {
  additional_auth_data auth = {};
  auth.session_id           = session_id;
  auth.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_w_ts.comp_or_compsubcomp_id.only_component_id.component_id
      = id;
  auth.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_w_ts.time_stamp = ts;
  auth.type_ = generic_comp_variations_::ONLY_COMP;
  return auth;
}

additional_auth_data construct_aad_frbv_comp_subcomp_nots(uint32_t comp_id,uint32_t subcomp_id) {
  additional_auth_data auth = {};
  auth.session_id           = session_id;
  auth.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_no_ts.comp_or_compsubcomp_id.subcomponent_id.component_id.component_id = comp_id;
  auth.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_no_ts.comp_or_compsubcomp_id.subcomponent_id.subcomponent_id = subcomp_id;
  auth.type_ = generic_comp_variations_::COMP_W_SUB_COMP_NO_CHANGE;
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
  auto mac      = builder.CreateVector((uint8_t*)&tag[0],SGX_CMAC_MAC_SIZE);

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
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  if (0) {
    res = sgx_read_rand((uint8_t*)pub_rand_root_seed.data(),
                           pub_rand_root_seed.size() * sizeof(uint64_t));
    CHECK_SGX_SUCCESS(res, "sgx_read_rand caused problem\n")
  }
  else {
    for (int i=0;i<16;++i) {
      pub_rand_root_seed[i] = 29;
    }
  }
  
  if (0) {
    res = sgx_read_rand((uint8_t*)sgx_rand_root_seed.data(),
                      sgx_rand_root_seed.size() * sizeof(uint64_t));
    CHECK_SGX_SUCCESS(res, "sgx_read_rand caused problem\n")

    res = sgx_read_rand((uint8_t*)&session_id, sizeof(session_id));
    CHECK_SGX_SUCCESS(res, "sgx_read_rand caused problem\n")
  }
  else {
    for (int i=0;i<16;++i) {
      sgx_rand_root_seed[i] = 19;
    }
    session_id = 1;
  }
  

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
      res = ocall_add_rand_integset(enc_auth_buff.data(), enc_auth_buff.size());
      CHECK_SGX_SUCCESS(res, "ocall_add_rand_integset caused problem!\n")
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

      if (!plain_image_label_auth_bytes) {
        plain_image_label_auth_bytes = std::unique_ptr<size_t>(new size_t);
        *plain_image_label_auth_bytes = auth_buff.size();
      }
      res = ocall_add_dec_images(auth_buff.data(), auth_buff.size());
      CHECK_SGX_SUCCESS(res, "ocall_add_dec_images caused problem!\n")

      not_chosen_count++;
    }
  }
  plain_dataset_size = not_chosen_count;
  integrity_set_dataset_size = chosen_count;
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
// forward: per single item in batch
// O_(filters,(out_w x out_h)) = 
//      W_(filters,(size x size x channels)) X 
//      I_((size x size x channels),(out_w x out_h)) 
// backward: per single item in batch 
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

void verify_init_net_config() {
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

void init_net() {
  if (*net_init_loader_ptr->net_context
      == net_context_variations::TRAINING_INTEGRITY_LAYERED_FIT) {
    net_init_training_integrity_layered_args args;
    args.verif_prob     = 1.0f;
    net_init_loader_ptr->invokable_params.init_train_integ_layered_params
        = args;
    net_init_loader_ptr->invokable.init_train_integ_layered(
        &net_init_loader_ptr->invokable_params.init_train_integ_layered_params);
  } else {
    LOG_DEBUG("not implemented\n")
  }
}

void send_batch_seed_to_gpu(const int iteration) {
  auto prng_seeds = get_iteration_seed(pub_root_rng->getState(), iteration);
  auto res        = ocall_gpu_get_iteration_seed(iteration,
                                          (uint8_t*)&prng_seeds.batch_layer_seed[0],
                                          sizeof(uint64_t) * 16,
                                          (uint8_t*)&prng_seeds.batch_layer_seed[16],
                                          sizeof(uint64_t) * 16);
  CHECK_SGX_SUCCESS(res,
                    "sending initial randomness before loading the network")
  LOG_DEBUG("for batch %d, the generated seeds for PRNGs are sent to gpu:\n"
    "1. <" COLORED_STR(RED,"%s") ">\n"
    "2. <" COLORED_STR(BRIGHT_GREEN,"%s") ">\n",
    iteration,bytesToHexString((uint8_t*)&prng_seeds.batch_layer_seed[0], 
      sizeof(uint64_t)*16).c_str(),
    bytesToHexString((uint8_t*)&((prng_seeds.batch_layer_seed)[16]), 
      sizeof(uint64_t)*16).c_str())
}

// TODO: Be careful if you do threading
void set_network_batch_randomness(const int iteration,network & net_) {
  auto prng_seeds = get_iteration_seed(pub_root_rng->getState(), iteration);
  LOG_DEBUG("for batch %d, enclaves PRNGs are :\n"
    "1. <" COLORED_STR(RED,"%s") ">\n"
    "2. <" COLORED_STR(BRIGHT_GREEN,"%s") ">\n",
    iteration,bytesToHexString((uint8_t*)&prng_seeds.batch_layer_seed[0], 
      sizeof(uint64_t)*16).c_str(),
    bytesToHexString((uint8_t*)&((prng_seeds.batch_layer_seed)[16]), 
      sizeof(uint64_t)*16).c_str())
  std::array<uint64_t,16> temp_seed;
  std::memcpy(temp_seed.data(),(uint8_t*)&prng_seeds.batch_layer_seed[0],sizeof(uint64_t)*16);
  net_.iter_batch_rng      = std::shared_ptr<PRNG>(new PRNG(temp_seed));
  std::memcpy(temp_seed.data(),(uint8_t*)&prng_seeds.batch_layer_seed[16],sizeof(uint64_t)*16);
  net_.layer_rng_deriver = std::shared_ptr<PRNG>(new PRNG(temp_seed));

  // LOG_DEBUG("inside\nnet_rng iter state : " COLORED_STR(RED,"%s\n") "layer_rng_deriver iter state: " COLORED_STR(BRIGHT_GREEN,"%s\n"),
  // bytesToHexString((const uint8_t*)net_.iter_batch_rng->getState().data(),sizeof(uint64_t)*16).c_str(),bytesToHexString((const uint8_t*)net_.layer_rng_deriver->getState().data(),sizeof(uint64_t)*16).c_str());
}

void init_net_train_integ_layered(const net_init_training_integrity_layered_args* args) {
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
  LOG_OUT(
      "Enclave loaded the network with following values\n"
      "enclave batch size   : %d\n"
      "enclave subdiv size  : %d\n"
      "processings per batch : %d\n",
      network_->batch,
      network_->enclave_subdivisions,
      (network_->batch * network_->enclave_subdivisions))
  auto verf_net_ = load_network(
      (char*)archconfigs.objPtr->mutable_contents()->Data(), nullptr, 1);
  verf_network_ = std::shared_ptr<network>(verf_net_, free_delete());
  LOG_OUT(
      "Enclave loaded the verfication network with following values\n"
      "enclave batch size   : %d\n"
      "enclave subdiv size  : %d\n"
      "processings per batch : %d\n",
      verf_network_->batch,
      verf_network_->enclave_subdivisions,
      (verf_network_->batch * verf_network_->enclave_subdivisions))
  // LOG_DEBUG("net_rng iter state : " COLORED_STR(RED,"%s\n") "layer_rng_deriver iter state: " COLORED_STR(BRIGHT_GREEN,"%s\n"),
  // bytesToHexString((const uint8_t*)network_->iter_batch_rng->getState().data(),sizeof(uint64_t)*16).c_str(),bytesToHexString((const uint8_t*)network_->layer_rng_deriver->getState().data(),sizeof(uint64_t)*16).c_str());
  
  // LOG_DEBUG("net_rng iter 0 first int : %d\n",network_->iter_batch_rng->getRandomInt());
  // LOG_DEBUG("layer_rng_deriver iter 0 first int : %d\n",network_->layer_rng_deriver->getRandomInt());
  // LOG_WARN("FIXME!\nnetwork structure and buffers must be managed with care!\n")
}

std::array<uint64_t, 16> generate_random_seed_from(PRNG &rng) {
  std::array<uint64_t, 16> temp_seed;
  std::memset(temp_seed.data(), 0, 16*sizeof(float));
  for (int j=0;j<16;++j) {
    temp_seed[j] = rng.getRandomUint64();
  }
  return temp_seed;
}

void setup_layers_iteration_seed(network& net, int iteration) {
  for (int i=0;i < net.n;++i) {
    net.layers[i].layer_rng = std::shared_ptr<PRNG>(new PRNG(generate_random_seed_from(*(net.layer_rng_deriver))));
  }
}

void apply_weight_updates_convolutional(int                     iteration,
                                   layer&                  l,
                                   int                     layer_index,
                                   sgx_sha_state_handle_t* sha256_handle) {
  uint64_t total_bytes   = count_layer_paramas_bytes(l);
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_sha(SGX_SHA256_HASH_SIZE, 0);
  sgx_sha_state_handle_t layer_updates_sha256_handle = nullptr;
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  // load bias updates
  {
    start = 0;
    end = l.bias_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    
    auto l_bias_updates
        = l.bias_updates->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,layer_index,buff_ind,
        (uint8_t*)l_bias_updates.get(),
        size_bytes,
        layer_sha.data(),
        SGX_SHA256_HASH_SIZE);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_bias_updates.get(), size_bytes, 
        layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
    }
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_bias_updates.get(),
                              size_bytes,
                              nullptr);
    l.bias_updates->setItemsInRange(
        start,end, l_bias_updates);
  }
  // LOG_DEBUG("passed bias!\n")
  // load weight updates
  {
    start = 0;
    end = l.weight_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    auto l_weight_updates
        = l.weight_updates->getItemsInRange(0, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,buff_ind,
        (uint8_t*)l_weight_updates.get(), size_bytes,nullptr,0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr,0, 
        0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_weight_updates.get(),
                              size_bytes,
                              nullptr);
    l.weight_updates->setItemsInRange(
        start,end, l_weight_updates);
  }
  // LOG_DEBUG("passed weights!\n")
  // batchnorm updates
  if (l.batch_normalize) {
    start = 0;
    end = l.scale_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    auto l_scale_updates
        = l.scale_updates->getItemsInRange(0, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,layer_index,buff_ind,
        (uint8_t*)l_scale_updates.get(),size_bytes,nullptr,0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_scale_updates.get(),
                              size_bytes,
                              nullptr);                  
    l.scale_updates->setItemsInRange(
        start,end, l_scale_updates);    

    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(0, end);

    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,layer_index,buff_ind,
        (uint8_t*)l_rolling_mean.get(),size_bytes,nullptr,0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }       
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_rolling_mean.get(),
                              size_bytes,
                              nullptr);
    l.rolling_mean->setItemsInRange(
        start,end, l_rolling_mean);

    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(0, end);
    
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,layer_index,buff_ind,
        (uint8_t*)l_rolling_variance.get(),size_bytes,nullptr,0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }

    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_rolling_variance.get(),
                              size_bytes,
                              nullptr);
    l.rolling_variance->setItemsInRange(
        start,end, l_rolling_variance);
  }
  // LOG_DEBUG("passed bn!\n")
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
 
  if (!verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              layer_sha.data(),
                              nullptr,
                              0,
                              nullptr)) {
    LOG_DEBUG("Layer sha256 computation did not match\n");
    abort();
  }
  // hash is part of the overall hash
  verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
  if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
    // grab hashes of MM results!
    OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0);
    verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);

    if (layer_index >=1 && network_->layers[layer_index-1].delta) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE);
      verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
    }
  }
}

void apply_weight_updates_connected(int iteration,layer& l,int layer_index, sgx_sha_state_handle_t* sha256_handle) {
  int enclave_update_batch = l.enclave_layered_batch / 2;
  int q = l.outputs / enclave_update_batch;
  int r = l.outputs % enclave_update_batch;
  uint64_t total_bytes   = count_layer_paramas_bytes(l);
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_sha(SGX_SHA256_HASH_SIZE, 0);
  sgx_sha_state_handle_t layer_updates_sha256_handle = nullptr;
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  // load bias updates
  {
    start = 0;
    end = l.bias_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    auto l_bias_updates
        = l.bias_updates->getItemsInRange(0, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_bias_updates.get(),
        size_bytes,
        layer_sha.data(),
        SGX_SHA256_HASH_SIZE);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_bias_updates.get(), size_bytes, 
        layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
    }
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_bias_updates.get(),
                              size_bytes,
                              nullptr);
    l.bias_updates->setItemsInRange(
        start,end, l_bias_updates);
  }

  // load weight updates
  {
    for (int i=0;i<q;++i) {
      start = i*enclave_update_batch*l.inputs;
      end = (i+1)*enclave_update_batch*l.inputs;
      size_bytes = (end - start)*sizeof(float);
      auto l_weight_updates = l.weight_updates->getItemsInRange(start,end);
      if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
        OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
          layer_index,
          buff_ind,
          (uint8_t*)l_weight_updates.get(),
          size_bytes,
          nullptr,
          0);
      }
      else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
          size_bytes, nullptr,0, 
          0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
      }
      
      buff_ind += size_bytes;
      verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_weight_updates.get(),
                              size_bytes,
                              nullptr);
      l.weight_updates->setItemsInRange(start, end,l_weight_updates);
    }
    if (r > 0) {
      start = q*enclave_update_batch*l.inputs;
      end = q*enclave_update_batch*l.inputs+r*l.inputs;
      size_bytes = (end - start)*sizeof(float);
      auto l_weight_updates = l.weight_updates->getItemsInRange(start,end);
      if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
        OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
          layer_index,
          buff_ind,
          (uint8_t*)l_weight_updates.get(),
          size_bytes,
          nullptr,
          0);
      }
      else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
          size_bytes, nullptr,0, 
          0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
      }
      
      buff_ind += size_bytes;
      verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_weight_updates.get(),
                              size_bytes,
                              nullptr);
      l.weight_updates->setItemsInRange(start, end,l_weight_updates);
    }
  }
  // batchnorm updates
  if (l.batch_normalize) {
    start = 0;
    end = l.scale_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    auto l_scale_updates
        = l.scale_updates->getItemsInRange(0, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_scale_updates.get(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
      size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    buff_ind += size_bytes;

    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_scale_updates.get(),
                              size_bytes,
                              nullptr);
    l.scale_updates->setItemsInRange(
        start,end, l_scale_updates);

    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(0, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_rolling_mean.get(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    buff_ind += size_bytes;

    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_rolling_mean.get(),
                              size_bytes,
                              nullptr);
    l.rolling_mean->setItemsInRange(
        start,end, l_rolling_mean);

    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(0, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_rolling_variance.get(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_rolling_variance.get(),
                              size_bytes,
                              nullptr);
    l.rolling_variance->setItemsInRange(
        start,end, l_rolling_variance);
  }
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
 
  if (!verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              layer_sha.data(),
                              nullptr,
                              0,
                              nullptr)) {
    LOG_DEBUG("Layer sha256 computation did not match\n");
    abort();
  }
  // hash is part of the overall hash
  verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);

  if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
    // grab hashes of MM results!
    OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0);
    verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);

    if (layer_index >=1 && network_->layers[layer_index-1].delta) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE);
      verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
    }
  }
}

void apply_weight_updates_batchnorm(int iteration,layer& l,int layer_index,sgx_sha_state_handle_t* sha256_handle) {
  uint64_t total_bytes   = count_layer_paramas_bytes(l);
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_sha(SGX_SHA256_HASH_SIZE, 0);
  sgx_sha_state_handle_t layer_updates_sha256_handle = nullptr;
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  {
    start = 0;
    end = l.scale_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    auto l_scale_updates
        = l.scale_updates->getItemsInRange(0, end);
    ret = ocall_load_layer_report_frbv(
        iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_scale_updates.get(),
        size_bytes,
        layer_sha.data(),
        SGX_SHA256_HASH_SIZE);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
    buff_ind += l.scale_updates->getBufferSize() * sizeof(float);
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_scale_updates.get(),
                              size_bytes,
                              nullptr);
    l.scale_updates->setItemsInRange(
        start,end, l_scale_updates);

    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(0, end);
    ret = ocall_load_layer_report_frbv(
        iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_rolling_mean.get(),
        size_bytes,
        nullptr,
        0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
    buff_ind += l.rolling_mean->getBufferSize() * sizeof(float);
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_rolling_mean.get(),
                              size_bytes,
                              nullptr);
    l.rolling_mean->setItemsInRange(
        start,end, l_rolling_mean);

    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(0, end);
    ret = ocall_load_layer_report_frbv(
        iteration,
        layer_index,
        buff_ind,
        (uint8_t*)l_rolling_variance.get(),
        size_bytes,
        nullptr,
        0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
    buff_ind += l.rolling_variance->getBufferSize() * sizeof(float);
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)l_rolling_variance.get(),
                              size_bytes,
                              nullptr);
    l.rolling_variance->setItemsInRange(
        start,end, l_rolling_variance);
  }
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
 
  if (!verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              layer_sha.data(),
                              nullptr,
                              0,
                              nullptr)) {
    LOG_DEBUG("Layer sha256 computation did not match\n");
    abort();
  }
  // hash is part of the overall hash
  verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
}

void apply_clipping_then_update(network* netp) {
  LOG_DEBUG("started apply_clipping_then_update \n")
  *netp->seen += netp->batch * (netp->enclave_subdivisions);
  netp->train     = 1;
  network     net = *netp;
  int         i;
  update_args a   = {0};
  a.batch         = net.batch * (net.enclave_subdivisions);
  a.learning_rate = get_current_rate(netp);
  a.momentum      = net.momentum;
  a.decay         = net.decay;
  a.adam          = net.adam;
  a.B1            = net.B1;
  a.B2            = net.B2;
  a.eps           = net.eps;
  a.grad_clip     = net.gradient_clip;
  ++*net.t;
  a.t = *net.t;

  for (i = 0; i < net.n; ++i) {
    layer l = net.layers[i];
    // LOG_DEBUG("processing update layer %d of %d with %d weights and %d biases
    // of type %s\n",i+1,net.n,l.nweights,l.nbiases,
    //         get_layer_string(l.type))
    if (l.update) {
      l.update(l, a);
    }
  }
  LOG_DEBUG("finished apply_clipping_then_update \n")
}

void apply_weight_updates(int iteration,network* net) {
  // get cmac on report hash
  // verify and get the report hash
  auto auth_report = std::vector<uint8_t>(SGX_SHA256_HASH_SIZE, 0);
  auto mac_report  = std::vector<uint8_t>(SGX_CMAC_MAC_SIZE, 0);
  additional_auth_data aad_report = {};
  auto                 ret        = ocall_load_auth_report(iteration,
                                         auth_report.data(),
                                         auth_report.size(),
                                         mac_report.data(),
                                         mac_report.size(),
                                         (uint8_t*)&aad_report,
                                         sizeof(aad_report));

  CHECK_SGX_SUCCESS(ret, "ocall_load_auth_report caused problem\n")
  if (!verify_cmac128_single_round(auth_report.data(),
                                   auth_report.size(),
                                   mac_report.data(),
                                   (uint8_t*)&aad_report,
                                   sizeof(aad_report))) {
    LOG_ERROR("could not verify valid cmac for the sh256\n");
    abort();
  }

  if (aad_report.type_ != generic_comp_variations::ONLY_COMP
      || aad_report.session_id != session_id
      || aad_report.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_w_ts
                 .comp_or_compsubcomp_id.only_component_id.component_id
             != iteration
      || aad_report.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_w_ts.time_stamp
             != iteration) {
    LOG_ERROR("aad data not valid\n");
    abort();  
  }
  LOG_DEBUG("apply_weight_updates cmac of sha256 is valid\n");
  sgx_sha_state_handle_t sha256_handle = nullptr;
  verify_sha256_mult_rounds(&sha256_handle,nullptr,nullptr,0,nullptr);
  for (int i=0;i<net->n;++i) {
    auto &l = net->layers[i];
    // LOG_DEBUG("processing layer %d of type %s\n",i,get_layer_string(l.type))
    if (l.type == CONVOLUTIONAL) {
      apply_weight_updates_convolutional(iteration,l,i,&sha256_handle);
    }
    else if (l.type == CONNECTED ) {
      apply_weight_updates_connected(iteration,l,i,&sha256_handle);
    }
    else if(l.type == BATCHNORM) {
      apply_weight_updates_batchnorm(iteration,l,i,&sha256_handle);
    }
  }
  if (!verify_sha256_mult_rounds(&sha256_handle,auth_report.data(),nullptr,0,nullptr)) {
    LOG_ERROR("overall hash of the layer snapshots cannot be verified!")
    abort();
  }
}

void save_load_params_and_update_snapshot_convolutional_frbv(bool save,int iteration,layer& l,int layer_index) {
  sgx_cmac_state_handle_t cmac_handle = nullptr;
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_cmac(SGX_CMAC_MAC_SIZE, 0);
  auto aad = construct_aad_frbv_comp_subcomp_nots(iteration,layer_index);
  size_t start =  0;
  size_t end   =  0;
  size_t size_bytes =0;
  size_t total_bytes = count_layer_paramas_updates_bytes(l);
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, nullptr, 0, nullptr, nullptr, 0);
  }
  else {
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, nullptr, 0, nullptr, nullptr, 0);
  }
  // bias and updates  
  {
    start = 0;
    end = l.biases->getBufferSize();
    size_bytes = (end - start)*sizeof(float);

    auto l_biases
        = l.biases->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_biases.get(), size_bytes, 
      nullptr, (uint8_t *)(&aad), sizeof(aad));
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_biases.get(),
      size_bytes, (uint8_t *)(&aad), sizeof(aad), nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_biases.get(),
      size_bytes, (uint8_t *)(&aad), sizeof(aad), nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_biases.get(), size_bytes, 
      nullptr, (uint8_t *)(&aad), sizeof(aad));
      l.biases->setItemsInRange(start,end,l_biases);
    }
    buff_ind += size_bytes;
    
    auto l_bias_updates
        = l.bias_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_bias_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_bias_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_bias_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_bias_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      l.bias_updates->setItemsInRange(start,end,l_bias_updates);
    }
    buff_ind += size_bytes;
  }
  // weights and updates
  {
    start = 0;
    end = l.weights->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    auto l_weights
        = l.weights->getItemsInRange(0, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_weights.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weights.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weights.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_weights.get(), size_bytes, 
      nullptr, nullptr,0);
      l.weights->setItemsInRange(start, end,l_weights);
    }
    buff_ind += size_bytes;

    auto l_weight_updates
        = l.weight_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_weight_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_weight_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      l.weight_updates->setItemsInRange(start, end,l_weight_updates);
    }
    buff_ind += size_bytes;
  }
  // batchnorm weights and updates
  if (l.batch_normalize) {
    // scales
    start = 0;
    end = l.scales->getBufferSize();
    size_bytes = (end - start)*sizeof(float);

    auto l_scales
        = l.scales->getItemsInRange(start, end);
    if(save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_scales.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scales.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scales.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_scales.get(), size_bytes, 
      nullptr, nullptr,0);
      l.scales->setItemsInRange(start, end, l_scales);
    }
    buff_ind += size_bytes;
  
    auto l_scale_updates
        = l.scale_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_scale_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_scale_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      // set items in range!
      l.scale_updates->setItemsInRange(start, end, l_scale_updates);
    }
    buff_ind += size_bytes;

    // rolling mean
    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_rolling_mean.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_rolling_mean.get(), size_bytes, 
      nullptr, nullptr,0);
      l.rolling_mean->setItemsInRange(start, end, l_rolling_mean);
    }
    buff_ind += size_bytes;
    // rolling variance
    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_rolling_variance.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_rolling_variance.get(), size_bytes, 
      nullptr, nullptr,0);
      l.rolling_variance->setItemsInRange(start, end, l_rolling_variance);
    }
    buff_ind += size_bytes;
  }
  if (buff_ind != total_bytes) {
    LOG_ERROR("size mismatch\n")
    abort();
  }
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, nullptr, 0, 
      layer_cmac.data(), nullptr, 0);
    OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, 0, nullptr,
      0, nullptr, 0, layer_cmac.data(), layer_cmac.size());
  }
  else {
    OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, 0, nullptr,
      0, nullptr, 0, layer_cmac.data(), layer_cmac.size());
    if (!gen_verify_cmac128_multiple_rounds(false,&cmac_handle, nullptr, 0, 
      layer_cmac.data(), nullptr, 0)) {
        LOG_ERROR("Layers cmac cannot be verified\n")
        abort();
      }
  }
}

void save_load_params_and_update_snapshot_connected_frbv(bool save,int iteration,layer& l,int layer_index) {
  sgx_cmac_state_handle_t cmac_handle = nullptr;
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_cmac(SGX_CMAC_MAC_SIZE, 0);
  auto aad = construct_aad_frbv_comp_subcomp_nots(iteration,layer_index);
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  size_t total_bytes = count_layer_paramas_updates_bytes(l);
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, nullptr, 0, nullptr, nullptr, 0);
  }
  else {
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, nullptr, 0, nullptr, nullptr, 0);
  }
  int enclave_update_batch = l.enclave_layered_batch / 2;
  int q = l.outputs / enclave_update_batch;
  int r = l.outputs % enclave_update_batch;
  // bias and updates 
  {
    start = 0;
    end = l.biases->getBufferSize();
    size_bytes = (end - start)*sizeof(float);

    auto l_biases
        = l.biases->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_biases.get(), size_bytes, 
      nullptr, (uint8_t *)(&aad), sizeof(aad));
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_biases.get(),
      size_bytes, (uint8_t *)(&aad), sizeof(aad), nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_biases.get(),
      size_bytes, (uint8_t *)(&aad), sizeof(aad), nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_biases.get(), size_bytes, 
      nullptr, (uint8_t *)(&aad), sizeof(aad));
      l.biases->setItemsInRange(start,end,l_biases);
    }
    buff_ind += size_bytes;
    
    auto l_bias_updates
        = l.bias_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_bias_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_bias_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_bias_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_bias_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      l.bias_updates->setItemsInRange(start,end,l_bias_updates);
    }
    buff_ind += size_bytes;
  }
  LOG_DEBUG("save_load_params_and_update_snapshot_connected_frbv save = %d, finished bias and bias_updates\n",save)
  // weights and updates
  for (int i=0;i<q;++i) {
    start = i*enclave_update_batch*l.inputs;
    end = (i+1)*enclave_update_batch*l.inputs;
    size_bytes = (end - start)*sizeof(float);
    LOG_DEBUG("save_load_params_and_update_snapshot_connected_frbv save = %d, i=%d, q=%d, r=%d weights in q\n",save,i,q,r)
    auto l_weights
        = l.weights->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_weights.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weights.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weights.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_weights.get(), size_bytes, 
      nullptr, nullptr,0);
      l.weights->setItemsInRange(start, end,l_weights);
    }
    buff_ind += size_bytes;
  }
  if (r > 0) {
    start = q*enclave_update_batch*l.inputs;
    end = q*enclave_update_batch*l.inputs+r*l.inputs;
    size_bytes = (end - start)*sizeof(float);
    LOG_DEBUG("save_load_params_and_update_snapshot_connected_frbv save = %d, q=%d, r=%d weights in r\n",save,q,r)
    auto l_weights
        = l.weights->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_weights.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weights.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weights.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_weights.get(), size_bytes, 
      nullptr, nullptr,0);
      l.weights->setItemsInRange(start, end,l_weights);
    }
    buff_ind += size_bytes;
  }
  LOG_DEBUG("save_load_params_and_update_snapshot_connected_frbv save = %d, finished weights\n",save)
  for (int i=0;i<q;++i) {
    start = i*enclave_update_batch*l.inputs;
    end = (i+1)*enclave_update_batch*l.inputs;
    size_bytes = (end - start)*sizeof(float);

    auto l_weight_updates
        = l.weight_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_weight_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_weight_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      l.weight_updates->setItemsInRange(start, end,l_weight_updates);
    }
    buff_ind += size_bytes;
  }
  if (r > 0) {
    start = q*enclave_update_batch*l.inputs;
    end = q*enclave_update_batch*l.inputs+r*l.inputs;
    size_bytes = (end - start)*sizeof(float);

    auto l_weight_updates
        = l.weight_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_weight_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_weight_updates.get(),
        size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_weight_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      l.weight_updates->setItemsInRange(start, end,l_weight_updates);
    }
    buff_ind += size_bytes;
  }
  LOG_DEBUG("save_load_params_and_update_snapshot_connected_frbv save = %d, finished weight_updates\n",save)
  // batchnorm weights and updates
  if (l.batch_normalize) {
    // scales
    start = 0;
    end = l.scales->getBufferSize();
    size_bytes = (end - start)*sizeof(float);

    auto l_scales
        = l.scales->getItemsInRange(start, end);
    if(save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_scales.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scales.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scales.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_scales.get(), size_bytes, 
      nullptr, nullptr,0);
      l.scales->setItemsInRange(start, end, l_scales);
    }
    buff_ind += size_bytes;
  
    auto l_scale_updates
        = l.scale_updates->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_scale_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_scale_updates.get(), size_bytes, 
      nullptr, nullptr,0);
      // set items in range!
      l.scale_updates->setItemsInRange(start, end, l_scale_updates);
    }
    buff_ind += size_bytes;

    // rolling mean
    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_rolling_mean.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_rolling_mean.get(), size_bytes, 
      nullptr, nullptr,0);
      l.rolling_mean->setItemsInRange(start, end, l_rolling_mean);
    }
    buff_ind += size_bytes;
    // rolling variance
    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(start, end);
    if (save) {
      gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_rolling_variance.get(), size_bytes, 
      nullptr, nullptr,0);
      OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
      size_bytes, nullptr, 0, nullptr, 0);
    }
    else {
      OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
      size_bytes, nullptr, 0, nullptr, 0);
      gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_rolling_variance.get(), size_bytes, 
      nullptr, nullptr,0);
      l.rolling_variance->setItemsInRange(start, end, l_rolling_variance);
    }
    buff_ind += size_bytes;
    LOG_DEBUG("save_load_params_and_update_snapshot_connected_frbv save = %d, finished bn stuff\n",save)
  }
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, nullptr, 0, 
      layer_cmac.data(), nullptr, 0);
    OCALL_SAVE_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, 0, nullptr,
      0, nullptr, 0, layer_cmac.data(), layer_cmac.size());
  }
  else {
    OCALL_LOAD_ENCLAVES_LAYER_PARAMS_UPDATES_FRBV(iteration, layer_index, 0, nullptr,
      0, nullptr, 0, layer_cmac.data(), layer_cmac.size());
    if (!gen_verify_cmac128_multiple_rounds(false,&cmac_handle, nullptr, 0, 
      layer_cmac.data(), nullptr, 0)) {
        LOG_ERROR("Layers cmac cannot be verified\n")
        abort();
      }
  }
}

void save_load_params_and_update_snapshot_batchnorm_frbv(bool save,int iteration,layer& l,int layer_index) {
  sgx_cmac_state_handle_t cmac_handle = nullptr;
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_cmac(SGX_CMAC_MAC_SIZE, 0);
  auto aad = construct_aad_frbv_comp_subcomp_nots(iteration,layer_index);
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  size_t total_bytes = count_layer_paramas_updates_bytes(l);
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, nullptr, 0, nullptr, nullptr, 0);
  }
  else {
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, nullptr, 0, nullptr, nullptr, 0);
  }
  // scales
  start = 0;
  end = l.scales->getBufferSize();
  size_bytes = (end - start)*sizeof(float);

  auto l_scales
      = l.scales->getItemsInRange(start, end);
  if(save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_scales.get(), size_bytes, 
    nullptr, nullptr,0);
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_scales.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  else {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_scales.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_scales.get(), size_bytes, 
    nullptr, nullptr,0);
    l.scales->setItemsInRange(start, end, l_scales);
  }
  buff_ind += size_bytes;

  auto l_scale_updates
      = l.scale_updates->getItemsInRange(start, end);
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_scale_updates.get(), size_bytes, 
    nullptr, nullptr,0);
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  else {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_scale_updates.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_scale_updates.get(), size_bytes, 
    nullptr, nullptr,0);
    // set items in range!
    l.scale_updates->setItemsInRange(start, end, l_scale_updates);
  }
  buff_ind += size_bytes;

  // rolling mean
  auto l_rolling_mean
      = l.rolling_mean->getItemsInRange(start, end);
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_rolling_mean.get(), size_bytes, 
    nullptr, nullptr,0);
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  else {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_mean.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_rolling_mean.get(), size_bytes, 
    nullptr, nullptr,0);
    l.rolling_mean->setItemsInRange(start, end, l_rolling_mean);
  }
  buff_ind += size_bytes;
  // rolling variance
  auto l_rolling_variance
      = l.rolling_variance->getItemsInRange(start, end);
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, (uint8_t*)l_rolling_variance.get(), size_bytes, 
    nullptr, nullptr,0);
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  else {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration, layer_index, buff_ind, (uint8_t*)l_rolling_variance.get(),
    size_bytes, nullptr, 0, nullptr, 0);
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    gen_verify_cmac128_multiple_rounds(false,&cmac_handle, (uint8_t*)l_rolling_variance.get(), size_bytes, 
    nullptr, nullptr,0);
    l.rolling_variance->setItemsInRange(start, end, l_rolling_variance);
  }
  buff_ind += size_bytes;
  
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
  if (save) {
    gen_verify_cmac128_multiple_rounds(true,&cmac_handle, nullptr, 0, 
      layer_cmac.data(), nullptr, 0);
    ret = ocall_save_enclaves_layer_params_updates_frbv(iteration, layer_index, 0, nullptr,
      0, nullptr, 0, layer_cmac.data(), layer_cmac.size());
    CHECK_SGX_SUCCESS(ret, "ocall_save_enclaves_layer_params_updates_frbv caused problem!\n")
  }
  else {
    ret = ocall_load_enclaves_layer_params_updates_frbv(iteration, layer_index, 0, nullptr,
      0, nullptr, 0, layer_cmac.data(), layer_cmac.size());
    CHECK_SGX_SUCCESS(ret, "ocall_load_enclaves_layer_params_updates_frbv caused problem!\n")
    if (!gen_verify_cmac128_multiple_rounds(false,&cmac_handle, nullptr, 0, 
      layer_cmac.data(), nullptr, 0)) {
        LOG_ERROR("Layers cmac cannot be verified\n")
        abort();
      }
  }
}

void save_load_params_and_update_snapshot_(bool save,int iteration, network* net) {
  
  for (int i=0;i<net->n;++i) {
    auto &l = net->layers[i];
    LOG_DEBUG("save_load_params_and_update_snapshot_ processing layer %d of type %s\n",i,get_layer_string(l.type))
    if (l.type == CONVOLUTIONAL) {
      save_load_params_and_update_snapshot_convolutional_frbv(save,iteration,l,i);
    }
    else if (l.type == CONNECTED ) {
      save_load_params_and_update_snapshot_connected_frbv(save,iteration,l,i);
    }
    else if(l.type == BATCHNORM) {
      save_load_params_and_update_snapshot_batchnorm_frbv(save,iteration,l,i);
    }
  }
}

float train_verify_in_enclave_frbv(int iteration,network* main_net,network* verf_net) {
  // do forward, backward
  *verf_net->seen = (iteration-1)*(verf_net->batch)*(verf_net->enclave_subdivisions);
  verf_net->train = 1;
  float avg_cost = 0;
  std::set<int> selected_ids;
  std::queue<int> queued_ids;
  while(true) {
    // Load input to the verf_network
    setup_iteration_inputs_training(queued_ids,selected_ids,verf_net,iteration,verf_net->batch,0,plain_dataset_size-1);
    *verf_net->seen += verf_net->batch;
    forward_network(verf_net);
    avg_cost += *verf_net->cost;
    LOG_DEBUG("cost sum this subdiv %f\n",avg_cost)
    backward_network(verf_net);
    if(((*verf_net->seen)/verf_net->batch)%verf_net->enclave_subdivisions == 0) {
      break;
    }
  }
  std::string indices = "verification selected indices of length " + std::to_string(selected_ids.size()) +" were:\n[";
  for (const auto ind:selected_ids) {
    indices += std::to_string(ind)+",";
  }
  indices += std::string("]\n");
  LOG_DEBUG("%s",indices.c_str())
  indices = "verification selected indices from [Queue] of length " + std::to_string(queued_ids.size()) +" were:\n[";
  while(!queued_ids.empty()){
    int ind = queued_ids.front();
    indices += std::to_string(ind)+",";
    queued_ids.pop();
  }
  indices += std::string("]\n");
  LOG_DEBUG("%s",indices.c_str())
  return avg_cost/(verf_net->enclave_subdivisions * (verf_net->batch));
}

void preload_MM_outputs_forward(network* net,int iteration,int enclave_subdiv) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  for(int i=0;i<net->n;++i) {
    layer &l = net->layers[i];
    if (l.type == CONNECTED) {
      size_t total_elems = l.output->getBufferSize();
      auto l_output = l.output->getItemsInRange(0, total_elems);
      size_t start = enclave_subdiv*total_elems*sizeof(float);
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration,i,
        0,nullptr,0,nullptr,0,
        start,(uint8_t*)l_output.get(),total_elems*sizeof(float),nullptr,0,
        0,nullptr,0,nullptr,0);
      l.output->setItemsInRange(0, total_elems, l_output);
    }
    else if (l.type == CONVOLUTIONAL) {
      size_t total_elems = l.output->getBufferSize();
      auto l_output = l.output->getItemsInRange(0, total_elems);
      size_t start = enclave_subdiv*total_elems*sizeof(float);
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration,i,
        0,nullptr,0,nullptr,0,
        start,(uint8_t*)l_output.get(),total_elems*sizeof(float),nullptr,0,
        0,nullptr,0,nullptr,0);
      // {
      //   const size_t interim_buff_size = (64 * ONE_KB);
      //   int q = (total_elems*sizeof(float)) / interim_buff_size;
      //   int r = (total_elems*sizeof(float)) % interim_buff_size;
      //   for (int j=0;j<q;++j) {
      //     ret = ocall_load_layer_report_frbmmv(iteration,i,
      //       0,nullptr,0,nullptr,0,
      //       start+j*interim_buff_size,(uint8_t*)l_output.get()+j*interim_buff_size,interim_buff_size,nullptr,0,
      //       0,nullptr,0,nullptr,0);
      //     CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
      //   }
      //   if (r != 0) {
      //     ret = ocall_load_layer_report_frbmmv(iteration,i,
      //       0,nullptr,0,nullptr,0,
      //       start+q*interim_buff_size,(uint8_t*)l_output.get()+q*interim_buff_size,r,nullptr,0,
      //       0,nullptr,0,nullptr,0);
      //     CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbmmv caused problem!\n")
      //   }
      // }
      l.output->setItemsInRange(0, total_elems, l_output);
    }
  }
}

void preload_MM_outputs_prev_delta_backward(network* net,int iteration,int enclave_subdiv) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  for(int i=0;i<net->n;++i) {
    layer &l = net->layers[i];
    if (l.type == CONNECTED) {
      // new MM prev delta
      if (i>=1 && net->layers[i-1].delta) {
        size_t total_elems = net->layers[i-1].delta->getBufferSize();
        auto net_delta = net->layers[i-1].delta->getItemsInRange(0, total_elems);
        size_t start = enclave_subdiv*total_elems*sizeof(float);
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration,i,0,nullptr,0,nullptr,0,0,nullptr,0,nullptr,0,
          start,(uint8_t*)net_delta.get(),total_elems*sizeof(float),nullptr,0);
        net->layers[i-1].delta->setItemsInRange(0, total_elems,net_delta);
      }
    }
  }
}

void preload_MM_weight_updates_backward(network* net,int iteration) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  for(int i=0;i<net->n;++i) {
    layer &l = net->layers[i];
    if (l.type == CONNECTED) {
      std::memset(l.right_rand_weight_updates, 0, sizeof(double)*l.outputs);
      for (int j=0;j<l.inputs;++j) {
        l.input_rand_weight_updates[j] = sgx_root_rng->getRandomFloat(std::numeric_limits<float>::min(),
                    std::numeric_limits<float>::max());
      }
      // new MM weight updates
      int q = l.outputs / l.enclave_layered_batch;
      int r = l.outputs % l.enclave_layered_batch;
      size_t start = (l.nbiases*sizeof(float));
      for (int j=0;j<q;++j) {
        auto l_weight_updates = l.weight_updates->getItemsInRange(j*l.enclave_layered_batch*l.inputs, 
                                                                  (j+1)*l.enclave_layered_batch*l.inputs);
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration,i,
          start+j*l.enclave_layered_batch*l.inputs*sizeof(float),
          (uint8_t*)l_weight_updates.get(),
          l.enclave_layered_batch*l.inputs*sizeof(float),
          nullptr,0,0,nullptr,0,nullptr,0,0,nullptr,0,nullptr,0);
        l.weight_updates->setItemsInRange(j*l.enclave_layered_batch*l.inputs, (j+1)*l.enclave_layered_batch*l.inputs,l_weight_updates);
      }
      if (r!=0) {
        auto l_weight_updates = l.weight_updates->getItemsInRange(q*l.enclave_layered_batch*l.inputs, q*l.enclave_layered_batch*l.inputs+r*l.inputs);
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration,i,
          start+q*l.enclave_layered_batch*l.inputs*sizeof(float),
          (uint8_t*)l_weight_updates.get(),
          r*l.inputs*sizeof(float),
          nullptr,0,0,nullptr,0,nullptr,0,0,nullptr,0,nullptr,0);
        l.weight_updates->setItemsInRange(q*l.enclave_layered_batch*l.inputs, q*l.enclave_layered_batch*l.inputs+r*l.inputs,l_weight_updates);
      }
    }
    else if (l.type == CONVOLUTIONAL) {
      // new MM weight updates
      std::memset(l.right_rand_weight_updates, 0, sizeof(double)*(l.n/l.groups));
      for (int j=0;j< (l.c / l.groups * l.size * l.size);++j) {
        l.input_rand_weight_updates[j] = sgx_root_rng->getRandomFloat(std::numeric_limits<float>::min(),
                    std::numeric_limits<float>::max());
      }
      size_t total_elements = l.weight_updates->getBufferSize();
      size_t start = (l.nbiases*sizeof(float));
      auto weight_updates = l.weight_updates->getItemsInRange(0, total_elements);
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration,i,start,(uint8_t*)weight_updates.get(),total_elements*sizeof(float)
        ,nullptr,0,0,nullptr,0,nullptr,0,0,nullptr,0,nullptr,0);
      l.weight_updates->setItemsInRange(0, total_elements, weight_updates);
    }
  }
}

float train_verify_in_enclave_frbmmv(int iteration,network* main_net,network* verf_net) {
  verf_net->sgx_net_verifies = 1;
  *verf_net->seen = (iteration-1)*(verf_net->batch)*(verf_net->enclave_subdivisions);
  verf_net->train = 1;
  float avg_cost = 0;
  int subdiv = 0;
  std::set<int> selected_ids;
  std::queue<int> queued_ids;
  preload_MM_weight_updates_backward(verf_net,iteration);
  while(true) {
    // Load input to the verf_network
    setup_iteration_inputs_training(queued_ids, selected_ids,verf_net,iteration,
        verf_net->batch,0,plain_dataset_size-1);
    *verf_net->seen += verf_net->batch;
    preload_MM_outputs_forward(verf_net,iteration,subdiv);
    LOG_DEBUG("ready for verification forward subdiv %d\n",subdiv)
    forward_network(verf_net);
    avg_cost += *verf_net->cost;
    LOG_DEBUG("cost sum this subdiv %f\n",avg_cost)
    preload_MM_outputs_prev_delta_backward(verf_net,iteration,subdiv);
    LOG_DEBUG("ready for verification backward subdiv %d\n",subdiv)
    backward_network(verf_net);
    subdiv++;
    if(((*verf_net->seen)/verf_net->batch)%verf_net->enclave_subdivisions == 0) {
      break;
    }
  }
  std::string indices = "verification selected indices of length " + std::to_string(selected_ids.size()) +" were:\n[";
  for (const auto ind:selected_ids) {
    indices += std::to_string(ind)+",";
  }
  indices += std::string("]\n");
  LOG_DEBUG("%s",indices.c_str())
  indices = "verification selected indices from [Queue] of length " + std::to_string(queued_ids.size()) +" were:\n[";
  while(!queued_ids.empty()){
    int ind = queued_ids.front();
    indices += std::to_string(ind)+",";
    queued_ids.pop();
  }
  indices += std::string("]\n");
  LOG_DEBUG("%s",indices.c_str())
  return avg_cost/(verf_net->enclave_subdivisions * (verf_net->batch));
}

bool float_equal(const float a,const float b) {
  if ((std::fabs(a - b)
          < 
          // std::numeric_limits<float>::epsilon()
          0.01f
                * std::fmax(std::fabs(a),
                            std::fabs(b))) || (std::fabs(a - b) < 0.05f)) {
                              return true;
                            }
  return false;
}

void compare_param_updates_convolutional(int iteration,network* verf_net,layer& l,int layer_index,sgx_sha_state_handle_t* sha256_handle) {
  uint64_t total_bytes   = count_layer_paramas_bytes(l);
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_sha(SGX_SHA256_HASH_SIZE, 0);
  sgx_sha_state_handle_t layer_updates_sha256_handle = nullptr;
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  std::vector<float> temp_vec;

  float max_diff = 0.0f;

  // load bias updates
  {
    start = 0;
    end = l.bias_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    temp_vec.resize((end - start));

    auto l_bias_updates
        = l.bias_updates->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        layer_sha.data(),
        SGX_SHA256_HASH_SIZE);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(), size_bytes, 
        layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_bias_updates[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_bias_updates[i])) {
        // LOG_ERROR("reported updates and computed for bias do not match! Layer %d of type %s, at index %u with difference %f, (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_bias_updates[i]),temp_vec[i],l_bias_updates[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for bias do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;
  }
  // load weight updates
  {
    start = 0;
    end = l.weight_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    temp_vec.resize((end - start));

    auto l_weight_updates
        = l.weight_updates->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes, nullptr,0, 
        0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_weight_updates[i]);
      if (diff > max_diff) {
          max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_weight_updates[i])) {
        // LOG_ERROR("reported updates and computed for weights do not match! Layer %d of type %s, at index %u with difference %f (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_weight_updates[i]),temp_vec[i],l_weight_updates[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for weights do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;
  }
  // batchnorm updates
  if (l.batch_normalize) {
    start = 0;
    end = l.scale_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    temp_vec.resize((end - start));

    auto l_scale_updates
        = l.scale_updates->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_scale_updates[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_scale_updates[i])) {
        // LOG_ERROR("reported updates and computed for scale updates do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_scale_updates[i]),temp_vec[i],l_scale_updates[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for scale updates do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;

    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_rolling_mean[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_rolling_mean[i])) {
        // LOG_ERROR("reported updates and computed for rolling mean do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_rolling_mean[i]),temp_vec[i],l_rolling_mean[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for rolling mean do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;

    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_rolling_variance[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_rolling_variance[i])) {
        // LOG_ERROR("reported updates and computed for rolling variance do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_rolling_variance[i]),temp_vec[i],l_rolling_variance[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for rolling variance do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;
  }
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
 
  if (!verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              layer_sha.data(),
                              nullptr,
                              0,
                              nullptr)) {
    LOG_DEBUG("Layer sha256 computation did not match\n");
    abort();
  }
  // hash is part of the overall hash
  verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
  if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
    // grab hashes of MM results!
    OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0);
    verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);

    if (layer_index >=1 && verf_net->layers[layer_index-1].delta) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE);
      verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
    }
  }
}

void compare_param_updates_connected(int iteration,network* verf_net,layer& l,int layer_index,sgx_sha_state_handle_t* sha256_handle) {
  int enclave_update_batch = l.enclave_layered_batch / 2;
  int q = l.outputs / enclave_update_batch;
  int r = l.outputs % enclave_update_batch;
  LOG_DEBUG(COLORED_STR(BRIGHT_YELLOW, "layer enclave batch for connected is %d with halved:%d,q=%d,r=%d,batch=%d,inputs=%d,outputs=%d\n"),
  l.enclave_layered_batch,enclave_update_batch,q,r,l.batch,l.inputs,l.outputs)
  uint64_t total_bytes   = count_layer_paramas_bytes(l);
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_sha(SGX_SHA256_HASH_SIZE, 0);
  sgx_sha_state_handle_t layer_updates_sha256_handle = nullptr;
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;

  float max_diff = 0.0f;

  std::vector<float> temp_vec;
  // load bias updates
  {
    start = 0;
    end = l.bias_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    temp_vec.resize((end - start));

    auto l_bias_updates
        = l.bias_updates->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        layer_sha.data(),
        SGX_SHA256_HASH_SIZE);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(), size_bytes, 
        layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0,nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_bias_updates[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_bias_updates[i])) {
        // LOG_ERROR("reported updates and computed for bias do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_bias_updates[i]),temp_vec[i],l_bias_updates[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for bias do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;
  }

  // load weight updates
  {
    for (int i=0;i<q;++i) {
      start = i*enclave_update_batch*l.inputs;
      end = (i+1)*enclave_update_batch*l.inputs;
      size_bytes = (end - start)*sizeof(float);
      temp_vec.resize((end - start));
      auto l_weight_updates = l.weight_updates->getItemsInRange(start,end);
      if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
        OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
          layer_index,
          buff_ind,
          (uint8_t*)temp_vec.data(),
          size_bytes,
          nullptr,
        0);
      }
      else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
          size_bytes, nullptr,0, 
          0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
      }
      
      buff_ind += size_bytes;
      verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
      for (uint32_t j = 0; j < (end - start); ++j) {
        auto diff = std::fabs(temp_vec[j] - l_weight_updates[j]);
        if (diff > max_diff) {
          max_diff = diff;
        }
        if (!float_equal(temp_vec[j],  l_weight_updates[j])) {
          // LOG_ERROR("reported updates and computed for weights do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
          //         layer_index,get_layer_string(l.type),j,std::fabs(temp_vec[j] - l_weight_updates[j]),temp_vec[j],l_weight_updates[j])
          // abort();
        }
      }
    }
    if (r > 0) {
      start = q*enclave_update_batch*l.inputs;
      end = q*enclave_update_batch*l.inputs+r*l.inputs;
      temp_vec.resize((end - start));
      size_bytes = (end - start)*sizeof(float);
      auto l_weight_updates = l.weight_updates->getItemsInRange(start,end);
      if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
        OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
          layer_index,
          buff_ind,
          (uint8_t*)temp_vec.data(),
          size_bytes,
          nullptr,
          0);
      }
      else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
        OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
          size_bytes, nullptr,0, 
          0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
      }
      
      buff_ind += size_bytes;
      verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
      for (uint32_t i = 0; i < (end - start); ++i) {
        auto diff = std::fabs(temp_vec[i] - l_weight_updates[i]);
        if (diff > max_diff) {
          max_diff = diff;
        }
        if (!float_equal(temp_vec[i], l_weight_updates[i])) {
          // LOG_ERROR("reported updates and computed for weights do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
          //         layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_weight_updates[i]),temp_vec[i],l_weight_updates[i])
          // abort();
        }
      }
    }
    LOG_DEBUG("reported updates and computed for weights do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;
  }
  // batchnorm updates
  if (l.batch_normalize) {
    start = 0;
    end = l.scale_updates->getBufferSize();
    size_bytes = (end - start)*sizeof(float);
    temp_vec.resize((end - start));

    auto l_scale_updates
        = l.scale_updates->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_scale_updates[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_scale_updates[i])) {
        // LOG_ERROR("reported updates and computed for scale updates do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_scale_updates[i]),temp_vec[i],l_scale_updates[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for scale updates do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;

    auto l_rolling_mean
        = l.rolling_mean->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_rolling_mean[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_rolling_mean[i])) {
        // LOG_ERROR("reported updates and computed for rolling mean do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_rolling_mean[i]),temp_vec[i],l_rolling_mean[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for rolling mean do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;

    auto l_rolling_variance
        = l.rolling_variance->getItemsInRange(start, end);
    if (*main_verf_task_variation_ == verf_variations_t::FRBV) {
      OCALL_LOAD_LAYER_REPRT_FRBV(iteration,
        layer_index,
        buff_ind,
        (uint8_t*)temp_vec.data(),
        size_bytes,
        nullptr,
        0);
    }
    else if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, buff_ind, (uint8_t*)temp_vec.data(),
        size_bytes,nullptr,0,0, nullptr, 0,nullptr, 0, 0, nullptr, 0, nullptr, 0);
    }
    
    buff_ind += size_bytes;
    verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              nullptr,
                              (uint8_t*)temp_vec.data(),
                              size_bytes,
                              nullptr);
    for (uint32_t i = 0; i < (end - start); ++i) {
      auto diff = std::fabs(temp_vec[i] - l_rolling_variance[i]);
      if (diff > max_diff) {
        max_diff = diff;
      }
      if (!float_equal(temp_vec[i],  l_rolling_variance[i])) {
        // LOG_ERROR("reported updates and computed for rolling variance do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
        //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_rolling_variance[i]),temp_vec[i],l_rolling_variance[i])
        // abort();
      }
    }
    LOG_DEBUG("reported updates and computed for rolling variance do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
    max_diff = 0.0f;
  }
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
 
  if (!verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              layer_sha.data(),
                              nullptr,
                              0,
                              nullptr)) {
    LOG_DEBUG("Layer sha256 computation did not match\n");
    abort();
  }
  // hash is part of the overall hash
  verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
  if (*main_verf_task_variation_ == verf_variations_t::FRBRMMV) {
    // grab hashes of MM results!
    OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE, 0, nullptr, 0, nullptr, 0);
    verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);

    if (layer_index >=1 && verf_net->layers[layer_index-1].delta) {
      OCALL_LOAD_LAYER_REPRT_FRBMMV(iteration, layer_index, 0, nullptr, 0, 
              nullptr, 0, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0, layer_sha.data(), SGX_SHA256_HASH_SIZE);
      verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
    }
  }
}

void compare_param_updates_batchnorm(int iteration,network* verf_net,layer& l,int layer_index,sgx_sha_state_handle_t* sha256_handle) {
  uint64_t total_bytes   = count_layer_paramas_bytes(l);
  size_t       buff_ind = 0;
  sgx_status_t ret      = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t>   layer_sha(SGX_SHA256_HASH_SIZE, 0);
  sgx_sha_state_handle_t layer_updates_sha256_handle = nullptr;
  size_t start = 0;
  size_t end = 0;
  size_t size_bytes =0;
  std::vector<float> temp_vec;

  float max_diff = 0.0f;

  start = 0;
  end = l.scale_updates->getBufferSize();
  size_bytes = (end - start)*sizeof(float);
  temp_vec.resize((end - start));

  auto l_scale_updates
      = l.scale_updates->getItemsInRange(start, end);
  ret = ocall_load_layer_report_frbv(
      iteration,
      layer_index,
      buff_ind,
      (uint8_t*)temp_vec.data(),
      size_bytes,
      nullptr,
      0);
  CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
  buff_ind += size_bytes;
  verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                            nullptr,
                            (uint8_t*)temp_vec.data(),
                            size_bytes,
                            nullptr);
  for (uint32_t i = 0; i < (end - start); ++i) {
    auto diff = std::fabs(temp_vec[i] - l_scale_updates[i]);
    if (diff > max_diff) {
      max_diff = diff;
    }
    if (!float_equal(temp_vec[i],  l_scale_updates[i])) {
      // LOG_ERROR("reported updates and computed for scale updates do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
      //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_scale_updates[i]),temp_vec[i],l_scale_updates[i])
      // abort();
    }
  }
  LOG_DEBUG("reported updates and computed for scale updates do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
  max_diff = 0.0f;

  auto l_rolling_mean
      = l.rolling_mean->getItemsInRange(start, end);
  ret = ocall_load_layer_report_frbv(
      iteration,
      layer_index,
      buff_ind,
      (uint8_t*)temp_vec.data(),
      size_bytes,
      nullptr,
      0);
  CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
  buff_ind += size_bytes;
  verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                            nullptr,
                            (uint8_t*)temp_vec.data(),
                            size_bytes,
                            nullptr);
  for (uint32_t i = 0; i < (end - start); ++i) {
    auto diff = std::fabs(temp_vec[i] - l_rolling_mean[i]);
    if (diff > max_diff) {
      max_diff = diff;
    }
    if (!float_equal(temp_vec[i],  l_rolling_mean[i])) {
      // LOG_ERROR("reported updates and computed for rolling mean do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
      //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_rolling_mean[i]),temp_vec[i],l_rolling_mean[i])
      // abort();
    }
  }
  LOG_DEBUG("reported updates and computed for rolling mean do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
  max_diff = 0.0f;

  auto l_rolling_variance
      = l.rolling_variance->getItemsInRange(start, end);
  ret = ocall_load_layer_report_frbv(
      iteration,
      layer_index,
      buff_ind,
      (uint8_t*)temp_vec.data(),
      size_bytes,
      nullptr,
      0);
  CHECK_SGX_SUCCESS(ret, "ocall_load_layer_report_frbv caused problem!\n")
  buff_ind += size_bytes;
  verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                            nullptr,
                            (uint8_t*)temp_vec.data(),
                            size_bytes,
                            nullptr);
  for (uint32_t i = 0; i < (end - start); ++i) {
    auto diff = std::fabs(temp_vec[i] - l_rolling_variance[i]);
    if (diff > max_diff) {
      max_diff = diff;
    }
    if (!float_equal(temp_vec[i],  l_rolling_variance[i])) {
      // LOG_ERROR("reported updates and computed for rolling variance do not match! Layer %d of type %s, at index %u with difference %f  (%f,%f)\n",
      //           layer_index,get_layer_string(l.type),i,std::fabs(temp_vec[i] - l_rolling_variance[i]),temp_vec[i],l_rolling_variance[i])
      // abort();
    }
  }
  LOG_DEBUG("reported updates and computed for rolling variance do not match! Layer %d of type %s with and max diff: %f\n",layer_index,get_layer_string(l.type),max_diff);
  max_diff = 0.0f;
  if (buff_ind != total_bytes) {
                LOG_ERROR("size mismatch\n")
                abort();
  }
 
  if (!verify_sha256_mult_rounds(&layer_updates_sha256_handle,
                              layer_sha.data(),
                              nullptr,
                              0,
                              nullptr)) {
    LOG_DEBUG("Layer sha256 computation did not match\n");
    abort();
  }
  // hash is part of the overall hash
  verify_sha256_mult_rounds(sha256_handle,nullptr,layer_sha.data(),layer_sha.size(),nullptr);
}

bool compare_param_updates_with_report_frbv(int iteration, network* verf_net) {
  
  // TODO: You can also compare the HASH value instead of comparing one by one
  // get cmac on report hash
  // verify and get the report hash
  auto auth_report = std::vector<uint8_t>(SGX_SHA256_HASH_SIZE, 0);
  auto mac_report  = std::vector<uint8_t>(SGX_CMAC_MAC_SIZE, 0);
  additional_auth_data aad_report = {};
  auto                 ret        = ocall_load_auth_report(iteration,
                                         auth_report.data(),
                                         auth_report.size(),
                                         mac_report.data(),
                                         mac_report.size(),
                                         (uint8_t*)&aad_report,
                                         sizeof(aad_report));

  CHECK_SGX_SUCCESS(ret, "ocall_load_auth_report caused problem\n")
  if (!verify_cmac128_single_round(auth_report.data(),
                                   auth_report.size(),
                                   mac_report.data(),
                                   (uint8_t*)&aad_report,
                                   sizeof(aad_report))) {
    LOG_ERROR("could not verify valid cmac for the sh256\n");
    abort();
    return false;
  }

  if (aad_report.type_ != generic_comp_variations::ONLY_COMP
      || aad_report.session_id != session_id
      || aad_report.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_w_ts
                 .comp_or_compsubcomp_id.only_component_id.component_id
             != iteration
      || aad_report.comp_compsubcomp_w_wo_ts.comp_or_subcompcom_w_ts.time_stamp
             != iteration) {
    LOG_ERROR("aad data not valid\n");
    abort();  
    return false;
  }
  LOG_DEBUG("apply_weight_updates cmac of sha256 is valid\n");
  sgx_sha_state_handle_t sha256_handle = nullptr;
  verify_sha256_mult_rounds(&sha256_handle,nullptr,nullptr,0,nullptr);
  for (int i=0;i<verf_net->n;++i) {
    // LOG_DEBUG("Proceeding comapring updates for index %d\n",i)
    auto &l = verf_net->layers[i];
    if (l.type == CONVOLUTIONAL) {
      compare_param_updates_convolutional(iteration, verf_net, l, i,&sha256_handle);
    }
    else if (l.type == CONNECTED ) {
      compare_param_updates_connected(iteration, verf_net, l, i,&sha256_handle);
    }
    else if(l.type == BATCHNORM) {
      compare_param_updates_batchnorm(iteration, verf_net, l, i,&sha256_handle);
    }
  }
  if (!verify_sha256_mult_rounds(&sha256_handle,auth_report.data(),nullptr,0,nullptr)) {
    LOG_ERROR("overall hash of the layer snapshots cannot be verified!\n")
    abort();
    return false;
  }
  return true;
}

void verify_task_frbv() {
  verf_task_t verf_task;
  auto found_task = task_queue.try_dequeue(verf_task);
  int iteration = verf_task.iter_id;
  if (found_task) {
    LOG_DEBUG("Found the task for iteration %d\n",iteration)
    set_network_batch_randomness(iteration,*verf_network_);
    setup_layers_iteration_seed(*verf_network_,iteration);
    if (iteration == 1) {
      // any other iteration except 1st
    }
    else {
      // load weights and final weight updates form step i - 1
      LOG_DEBUG(COLORED_STR(RED, "loading weights and updates from previous iteration: %d\n"),iteration-1)
      save_load_params_and_update_snapshot_(false,iteration-1,verf_network_.get());
    }

    // do forward, backward
    auto avg_cost = train_verify_in_enclave_frbv(iteration,network_.get(),verf_network_.get());
    LOG_DEBUG(COLORED_STR(BRIGHT_RED, "Verification: average cost for iteration %d is : %f\n"),iteration,avg_cost)
    // compare weight updates with with reported ones
    
    if (!compare_param_updates_with_report_frbv(iteration,verf_network_.get())){

    }
    else {
      LOG_OUT("Verified iteration %d\n",iteration)
    }
    // delete info before step i: i-1 so forth
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ocall_delete_snapshots_after_verification(iteration);
    CHECK_SGX_SUCCESS(ret, "ocall_delete_snapshots_after_verification caused problem!\n")
  }
}

void verify_task_frbmmv() {
  verf_task_t verf_task;
  auto found_task = task_queue.try_dequeue(verf_task);
  int iteration = verf_task.iter_id;
  if (found_task) {
    LOG_DEBUG("Found the task for iteration %d\n",iteration)
    set_network_batch_randomness(iteration,*verf_network_);
    setup_layers_iteration_seed(*verf_network_,iteration);
    if (iteration == 1) {
      // any other iteration except 1st
    }
    else {
      // load weights and final weight updates form step i - 1
      LOG_DEBUG(COLORED_STR(RED, "loading weights and updates from previous iteration: %d\n"),iteration-1)
      save_load_params_and_update_snapshot_(false,iteration-1,verf_network_.get());
    }

    // do forward, backward
    auto avg_cost = train_verify_in_enclave_frbmmv(iteration,network_.get(),verf_network_.get());
    LOG_DEBUG(COLORED_STR(BRIGHT_RED, "Verification: average cost for iteration %d is : %f\n"),iteration,avg_cost)
    // compare weight updates with with reported ones
    
    if (!compare_param_updates_with_report_frbv(iteration,verf_network_.get())){

    }
    else {
      LOG_OUT("Verified iteration %d\n",iteration)
    }
    // delete info before step i: i-1 so forth
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ocall_delete_snapshots_after_verification(iteration);
    CHECK_SGX_SUCCESS(ret, "ocall_delete_snapshots_after_verification caused problem!\n")
  }
}

void setup_iteration_inputs_training(std::queue<int>& queued_ids, std::set<int> &selected_ids_prev, network* net,
                                     int iteration, int size,int low,int high) {
  std::queue<int> selected_ids;
  // LOG_DEBUG("preparing inputs for verification network in iteration %d,low:%d,high:%d\n",iteration,low,high)
  while (selected_ids.size() < size) {
    int id = net->iter_batch_rng->getRandomInt(low, high);
    if (selected_ids_prev.count(id) == 0) {
      selected_ids_prev.insert(id);
      selected_ids.push(id);
      queued_ids.push(id);
    }
  }
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int ind = 0;
  const auto required_img_elems = dsconfigs.objPtr->img_label_meta()->image_meta()->width() *
  dsconfigs.objPtr->img_label_meta()->image_meta()->height() *
  dsconfigs.objPtr->img_label_meta()->image_meta()->channels() ;
  const auto required_img_bytes = required_img_elems * sizeof(float);
  const auto required_lbl_elems = dsconfigs.objPtr->img_label_meta()->label_meta()->numClasses();
  const auto required_lbl_byets = required_lbl_elems * sizeof(float);
  std::vector<uint8_t> cont_bytes(*plain_image_label_auth_bytes,0);
  auto net_input = net->input->getItemsInRange(0, net->input->getBufferSize());
  auto net_truth = net->truth->getItemsInRange(0, net->truth->getBufferSize());
  while(!selected_ids.empty()) {
  // for (const auto id : selected_ids) {
    int id = selected_ids.front();
    ret = ocall_load_dec_images(id,cont_bytes.data(),cont_bytes.size());
    CHECK_SGX_SUCCESS(ret, "ocall_load_dec_images caused problem\n")
    auto auth_buff = flatbuffers::GetRoot<CMAC128Auth>(cont_bytes.data());
    auto auth = construct_aad_input_nochange(id);
    if (!verify_cmac128_single_round(auth_buff->content()->Data(), auth_buff->content()->size(), 
      auth_buff->mac()->Data(), (uint8_t*)&auth,sizeof(auth))) {
        LOG_ERROR("cmac12 for image with id %d not verified\n",id);
        abort();
    }
    auto imglabel = flatbuffers::GetRoot<PlainImageLabel>(auth_buff->content()->Data());
    std::memcpy(net_input.get()+(ind*required_img_elems), imglabel->img_content()->Data(), required_img_bytes);

    if (net->truth) {
      std::memcpy(net_truth.get()+(ind*required_lbl_elems), imglabel->label_content()->Data(), required_lbl_byets);
    }
    ++ind;
    selected_ids.pop();
  }
  net->input->setItemsInRange(0, net->input->getBufferSize(),net_input);
  net->truth->setItemsInRange(0, net->truth->getBufferSize(),net_truth);
}

void start_training_verification_frbv(int iteration) {
  // sgx_sha256_hash_t report;
  std::vector<uint8_t> report(SGX_SHA256_HASH_SIZE,0);
  send_batch_seed_to_gpu(iteration);
  set_network_batch_randomness(iteration,*network_);
  setup_layers_iteration_seed(*network_,iteration);
  auto ret = ocall_gpu_train_report_frbv(iteration,report.data(),SGX_SHA256_HASH_SIZE);
  CHECK_SGX_SUCCESS(ret, "ocall_gpu_train_report_frbv caused an issue\n");
  // get a cmac on the report with iteration and put it outisde
  auto aad_report = construct_aad_frbv_report_nochange_ts(iteration, iteration);
  sgx_cmac_state_handle_t cmac_handle = nullptr;
  ret = sgx_cmac128_init(&enclave_cmac_key, &cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_init caused problem!\n")
  auto auth_report = generate_auth_flatbuff(report, &aad_report, &cmac_handle);
  ret = sgx_cmac128_close(cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_close caused problem!\n")
  // save_auth_step_report outside
  ret = ocall_save_auth_report_frbv(iteration,auth_report.data(),auth_report.size());
  CHECK_SGX_SUCCESS(ret, "ocall_save_auth_report_frbv caused problem!\n")
  // apply the computed updates (in GPU) that will be added up to weights step in enclave
  apply_weight_updates(iteration, network_.get());
  apply_clipping_then_update(network_.get());

  // snapshot weights and updates afterwards so maybe used for verification
  save_load_params_and_update_snapshot_(true,iteration,network_.get());
  
  // in case you do not want GPU performing update phase, let the GPU get the updates from SGX
  ret = ocall_use_sgx_new_weights_momentum_grads(iteration);
  CHECK_SGX_SUCCESS(ret, "ocall_use_sgx_new_weights_momentum_grads caused problem!\n")
  
  if (1) {
    // check if it should be added to verification queue
    const auto verf_rand = sgx_root_rng->getRandomFloat(0.0,1.0);
    verf_task_t task;
    task.iter_id = iteration;
    task.verf_ = verf_variations_t::FRBV;
    std::memcpy(task.task.frvb_task.reported_hash, report.data(), SGX_SHA256_HASH_SIZE);
    if (verf_rand <= net_init_loader_ptr->invokable_params.init_train_integ_layered_params.verif_prob) {
      task_queue.enqueue(task);
      LOG_DEBUG("Task has been put for verification!\n")
      verify_task_frbv();
    }
    else {
      LOG_DEBUG("Task has not been put for verification!\n")
    }
  }
  // abort();

  // if q has element try verifying to see
  // load weights and final weight updates form step i - 1
  // do forward, backward
  // compare weight updates with with reported ones
}

void start_training_verification_frbmmv(int iteration) {

  std::vector<uint8_t> report(SGX_SHA256_HASH_SIZE,0);
  send_batch_seed_to_gpu(iteration);
  set_network_batch_randomness(iteration,*network_);
  setup_layers_iteration_seed(*network_,iteration);
  auto ret = ocall_gpu_train_report_frbmmv(iteration,report.data(),SGX_SHA256_HASH_SIZE);
  CHECK_SGX_SUCCESS(ret, "ocall_gpu_train_report_frbmmv caused an issue\n");
  // get a cmac on the report with iteration and put it outisde
  auto aad_report = construct_aad_frbv_report_nochange_ts(iteration, iteration);
  sgx_cmac_state_handle_t cmac_handle = nullptr;
  ret = sgx_cmac128_init(&enclave_cmac_key, &cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_init caused problem!\n")
  auto auth_report = generate_auth_flatbuff(report, &aad_report, &cmac_handle);
  ret = sgx_cmac128_close(cmac_handle);
  CHECK_SGX_SUCCESS(ret, "sgx_cmac128_close caused problem!\n")
  // save_auth_step_report outside
  ret = ocall_save_auth_report_frbmmv(iteration,auth_report.data(),auth_report.size());
  CHECK_SGX_SUCCESS(ret, "ocall_save_auth_report_frbmmv caused problem!\n")
  // apply the computed updates (in GPU) that will be added up to weights step in enclave
  apply_weight_updates(iteration, network_.get());
  apply_clipping_then_update(network_.get());

  // snapshot weights and updates afterwards so maybe used for verification
  save_load_params_and_update_snapshot_(true,iteration,network_.get());
  
  // in case you do not want GPU performing update phase, let the GPU get the updates from SGX
  ret = ocall_use_sgx_new_weights_momentum_grads(iteration);
  CHECK_SGX_SUCCESS(ret, "ocall_use_sgx_new_weights_momentum_grads caused problem!\n")
  if (1) {
    // check if it should be added to verification queue
    const auto verf_rand = sgx_root_rng->getRandomFloat(0.0,1.0);
    verf_task_t task;
    task.iter_id = iteration;
    task.verf_ = verf_variations_t::FRBRMMV;
    std::memcpy(task.task.frvb_task.reported_hash, report.data(), SGX_SHA256_HASH_SIZE);
    if (verf_rand <= net_init_loader_ptr->invokable_params.init_train_integ_layered_params.verif_prob) {
      task_queue.enqueue(task);
      LOG_DEBUG("Task has been put for verification!\n")
      verify_task_frbmmv();
    }
    else {
      LOG_DEBUG("Task has not been put for verification!\n")
    }
  }
}
