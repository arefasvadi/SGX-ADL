cmake_minimum_required(VERSION 3.8)
project(SGX_DDL)

#set(CUSTOM_ENABLE_DEBUGING ON)

set(CUSTOM_ENABLE_LAYERWISE ON)
#set(CUSTOM_ENABLE_BLOCKING ON)
#set(CUSTOM_ENABLE_PURE_SGX ON)


if (CUSTOM_ENABLE_PURE_SGX)
  set(CUSTOM_ENABLE_LAYERWISE OFF)
  set(CUSTOM_ENABLE_BLOCKING OFF)
  set(DARKNET_SGX_MODE PURE_SGX)
elseif(CUSTOM_ENABLE_LAYERWISE)
  set(CUSTOM_ENABLE_PURE_SGX OFF)
  set(CUSTOM_ENABLE_BLOCKING OFF)
  set(DARKNET_SGX_MODE SGX_LAYERWISE)
elseif(CUSTOM_ENABLE_BLOCKING)
  set(CUSTOM_ENABLE_PURE_SGX OFF)
  set(CUSTOM_ENABLE_LAYERWISE OFF)
  set(DARKNET_SGX_MODE SGX_BLOCKING)
else()
  message(FATAL_ERROR "DARKNET_SGX_MODE cannot  be set properly!")
endif()


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(Threads REQUIRED)
find_library(SSL_LIB libssl.a REQUIRED)
find_library(CRYPTO_LIB libcrypto.a REQUIRED)

set(Untrusted_Home "${PROJECT_SOURCE_DIR}/untrusted")
set(Trusted_Home "${PROJECT_SOURCE_DIR}/trusted")
set(Scripts_Home "${PROJECT_SOURCE_DIR}/scripts")

set(Untrusted_Name "sgxdnnapp")
set(Trusted_Name "sgxdnn.enclave")
set(Signed_Trusted_Name "sgxdnn.enclave.signed.so")

set(Trusted_Config_File "${Trusted_Home}/enclave.config.xml")
set(Trusted_Edl "${Trusted_Home}/enclave.edl")
set(Private_Key_File "${Trusted_Home}/private_key.pem")

set(SGX_HW ON)
if (CUSTOM_ENABLE_DEBUGING)
  set(SGX_MODE "Debug")
  #set(CMAKE_BUILD_TYPE "Debug")
else()
  set(SGX_MODE "PreRelease")
  #set(SGX_MODE "Release")
  #set(CMAKE_BUILD_TYPE "Release")
endif()

if(SGX_HW AND SGX_MODE STREQUAL "Release")
    set(LDS "${Trusted_Home}/enclave-release.lds")
    set(Trusted_Config_File "${Trusted_Home}/enclave.config.HW-Release.xml")
else()
    set(LDS "${Trusted_Home}/enclave-debug.lds")
    set(Trusted_Config_File "${Trusted_Home}/enclave.config.xml")
endif()

find_package(SGX REQUIRED)

include_directories("${PROJECT_SOURCE_DIR}/include")

set(DARKNET_SOURCE_FILES
"third_party/darknet/src/gemm.cpp"
"third_party/darknet/src/utils.cpp"
"third_party/darknet/src/im2col.cpp"
"third_party/darknet/src/cuda.cpp"
"third_party/darknet/src/deconvolutional_layer.cpp"
"third_party/darknet/src/convolutional_layer.cpp"
"third_party/darknet/src/list.cpp"
"third_party/darknet/src/image.cpp"
"third_party/darknet/src/activations.cpp"
"third_party/darknet/src/col2im.cpp"
"third_party/darknet/src/blas.cpp"
"third_party/darknet/src/crop_layer.cpp"
"third_party/darknet/src/dropout_layer.cpp"
"third_party/darknet/src/maxpool_layer.cpp"
"third_party/darknet/src/softmax_layer.cpp"
"third_party/darknet/src/data.cpp"
"third_party/darknet/src/matrix.cpp"
"third_party/darknet/src/network.cpp"
"third_party/darknet/src/connected_layer.cpp"
"third_party/darknet/src/cost_layer.cpp"
"third_party/darknet/src/parser.cpp"
"third_party/darknet/src/option_list.cpp"
"third_party/darknet/src/detection_layer.cpp"
"third_party/darknet/src/route_layer.cpp"
"third_party/darknet/src/upsample_layer.cpp"
"third_party/darknet/src/box.cpp"
"third_party/darknet/src/normalization_layer.cpp"
"third_party/darknet/src/avgpool_layer.cpp"
"third_party/darknet/src/layer.cpp"
"third_party/darknet/src/local_layer.cpp"
"third_party/darknet/src/shortcut_layer.cpp"
"third_party/darknet/src/logistic_layer.cpp"
"third_party/darknet/src/activation_layer.cpp"
"third_party/darknet/src/rnn_layer.cpp"
"third_party/darknet/src/gru_layer.cpp"
"third_party/darknet/src/crnn_layer.cpp"
"third_party/darknet/src/demo.cpp"
"third_party/darknet/src/batchnorm_layer.cpp"
"third_party/darknet/src/region_layer.cpp"
"third_party/darknet/src/reorg_layer.cpp"
"third_party/darknet/src/tree.cpp"
"third_party/darknet/src/lstm_layer.cpp"
"third_party/darknet/src/l2norm_layer.cpp"
"third_party/darknet/src/yolo_layer.cpp"
)

set(DARKNET_SOURCE_FILES_SGX ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_SOURCE_FILES_SGX
  "third_party/darknet/src/cuda.cpp"
  "third_party/darknet/src/deconvolutional_layer.cpp"
  "third_party/darknet/src/detection_layer.cpp"
  "third_party/darknet/src/route_layer.cpp"
  "third_party/darknet/src/upsample_layer.cpp"
  "third_party/darknet/src/box.cpp"
  #"third_party/darknet/src/normalization_layer.cpp"
  #"third_party/darknet/src/local_layer.cpp"
  #"third_party/darknet/src/shortcut_layer.cpp"
  #"third_party/darknet/src/logistic_layer.cpp"
  "third_party/darknet/src/rnn_layer.cpp"
  "third_party/darknet/src/gru_layer.cpp"
  "third_party/darknet/src/crnn_layer.cpp"
  "third_party/darknet/src/demo.cpp"
  "third_party/darknet/src/region_layer.cpp"
  "third_party/darknet/src/reorg_layer.cpp"
  "third_party/darknet/src/tree.cpp"
  "third_party/darknet/src/lstm_layer.cpp"
  "third_party/darknet/src/l2norm_layer.cpp"
   "third_party/darknet/src/yolo_layer.cpp"
)

set(DARKNET_SOURCE_FILES_SGX_LAYERWISE ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_SOURCE_FILES_SGX_LAYERWISE 
  "third_party/darknet/src/cuda.cpp"
  "third_party/darknet/src/deconvolutional_layer.cpp"
  "third_party/darknet/src/detection_layer.cpp"
  "third_party/darknet/src/route_layer.cpp"
  "third_party/darknet/src/upsample_layer.cpp"
  "third_party/darknet/src/box.cpp"
  "third_party/darknet/src/normalization_layer.cpp"
  "third_party/darknet/src/local_layer.cpp"
  "third_party/darknet/src/shortcut_layer.cpp"
  "third_party/darknet/src/logistic_layer.cpp"
  "third_party/darknet/src/rnn_layer.cpp"
  "third_party/darknet/src/gru_layer.cpp"
  "third_party/darknet/src/crnn_layer.cpp"
  "third_party/darknet/src/demo.cpp"
  "third_party/darknet/src/region_layer.cpp"
  "third_party/darknet/src/reorg_layer.cpp"
  "third_party/darknet/src/tree.cpp"
  "third_party/darknet/src/lstm_layer.cpp"
  "third_party/darknet/src/l2norm_layer.cpp"
  "third_party/darknet/src/yolo_layer.cpp"
)

set(DARKNET_SOURCE_FILES_SGX_BLOCK ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_SOURCE_FILES_SGX_BLOCK 
  "third_party/darknet/src/cuda.cpp"
  "third_party/darknet/src/deconvolutional_layer.cpp"
  "third_party/darknet/src/detection_layer.cpp"
  "third_party/darknet/src/route_layer.cpp"
  "third_party/darknet/src/upsample_layer.cpp"
  "third_party/darknet/src/box.cpp"
  #"third_party/darknet/src/normalization_layer.cpp"
  "third_party/darknet/src/local_layer.cpp"
  #"third_party/darknet/src/shortcut_layer.cpp"
  #"third_party/darknet/src/logistic_layer.cpp"
  "third_party/darknet/src/rnn_layer.cpp"
  "third_party/darknet/src/gru_layer.cpp"
  "third_party/darknet/src/crnn_layer.cpp"
  "third_party/darknet/src/demo.cpp"
  "third_party/darknet/src/region_layer.cpp"
  "third_party/darknet/src/reorg_layer.cpp"
  "third_party/darknet/src/tree.cpp"
  "third_party/darknet/src/lstm_layer.cpp"
  "third_party/darknet/src/l2norm_layer.cpp"
  "third_party/darknet/src/yolo_layer.cpp"
)

add_trusted_library(DARKNET_T 
  SRCS 
    $<$<STREQUAL:${DARKNET_SGX_MODE},PURE_SGX>:${DARKNET_SOURCE_FILES_SGX}>
    $<$<STREQUAL:${DARKNET_SGX_MODE},SGX_LAYERWISE>:${DARKNET_SOURCE_FILES_SGX_LAYERWISE}>
    $<$<STREQUAL:${DARKNET_SGX_MODE},SGX_BLOCKING>:${DARKNET_SOURCE_FILES_SGX_BLOCK}>
    ${Trusted_Home}/src/darknet-addons.cpp 
    ${Trusted_Home}/src/pcg_basic.c
  EDL
    ${Trusted_Edl}
  EDL_SEARCH_PATHS
    ${SGX_SDK}/include
  LDSCRIPT
    ${LDS}
)
target_include_directories(DARKNET_T PUBLIC
  "${CMAKE_SOURCE_DIR}/include"  
  "${Trusted_Home}"
  "${Trusted_Home}/include"
)
target_compile_definitions(DARKNET_T PUBLIC USE_SGX $<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING> $<$<BOOL:${CUSTOM_ENABLE_LAYERWISE}>:USE_SGX_LAYERWISE>)

set(Enclave_Cpp_Files
  "${Trusted_Home}/src/bitonic-sort.cpp" 
  "${Trusted_Home}/src/enclave-app.cpp"
  "${Trusted_Home}/src/DNNConfigIO.cpp" 
  "${Trusted_Home}/src/DNNTrainer.cpp" 
  "${Trusted_Home}/src/BlockHeader.cpp" 
  "${Trusted_Home}/src/IBlockable.cpp" 
  "${Trusted_Home}/src/util.cpp" 
  "${Trusted_Home}/src/tests.cpp"
  "${Trusted_Home}/src/SpecialBufferCommon.cpp"
  )
add_enclave_library(
  ${Trusted_Name}
  SRCS
    ${Enclave_Cpp_Files}
  EDL
    ${Trusted_Edl}
  EDL_SEARCH_PATHS
    ${SGX_SDK}/include
  TRUSTED_LIBS
    DARKNET_T
  LDSCRIPT
    ${LDS}
)
target_compile_definitions(${Trusted_Name} PUBLIC USE_SGX $<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING> $<$<BOOL:${CUSTOM_ENABLE_LAYERWISE}>:USE_SGX_LAYERWISE>)
target_include_directories(${Trusted_Name} PUBLIC
  "${CMAKE_SOURCE_DIR}/include"
  "${Trusted_Home}/"
  "${Trusted_Home}/include"
  )
enclave_sign(
  ${Trusted_Name}
  KEY 
    ${Private_Key_File}
  CONFIG 
    ${Trusted_Config_File}
  OUTPUT 
    ${Signed_Trusted_Name})

set(App_Cpp_Files
  "${Untrusted_Home}/src/app.cpp"
  "${Untrusted_Home}/src/load-image.cpp"
  "third_party/darknet/src/data.cpp"
  "third_party/darknet/src/utils.cpp"
  "third_party/darknet/src/list.cpp"
  "third_party/darknet/src/image.cpp"
  "third_party/darknet/src/matrix.cpp"
  "third_party/darknet/src/list.cpp"
  "third_party/darknet/src/blas.cpp"
  )
  add_untrusted_executable(
    ${Untrusted_Name}
    SRCS 
      ${App_Cpp_Files}
    EDL
      ${Trusted_Edl}
    EDL_SEARCH_PATHS
      ${SGX_SDK}/include
  )
  target_include_directories(${Untrusted_Name} PUBLIC
  "${CMAKE_SOURCE_DIR}/include"
  "${Untrusted_Home}"
  "${Untrusted_Home}/include"
  "third_party/darknet/include")
  target_link_libraries(${Untrusted_Name} "crypto" "pthread")