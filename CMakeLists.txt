cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(SGX_ADL LANGUAGES C CXX CUDA)

#set(CMAKE_CXX_CLANG_TIDY 
#  clang-tidy;
  #-header-filter=.;
#  -checks=*,readability-*;)

set(CUSTOM_ENABLE_DEBUGING ON)

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
option(CUDA_VERBOSE_BUILD "Create verbose CUDA build" ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CUDA_STANDARD 14)


list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
#find_library(SSL_LIB libssl.a REQUIRED)
#find_library(CRYPTO_LIB libcrypto.a REQUIRED)

# adding google test framework
enable_testing()
find_package(GTest REQUIRED)

set(Untrusted_Home "${PROJECT_SOURCE_DIR}/untrusted")
set(Trusted_Home "${PROJECT_SOURCE_DIR}/trusted")
set(Scripts_Home "${PROJECT_SOURCE_DIR}/scripts")

set(Untrusted_Name "sgxdnnapp")
set(Untrusted_Lib_Name "sgxdnnapplib")

set(Trusted_Name "sgxdnn.enclave")
set(Signed_Trusted_Name "sgxdnn.enclave.signed.so")

set(Trusted_Config_File "${Trusted_Home}/enclave.config.xml")
set(Trusted_Edl "${Trusted_Home}/enclave.edl")
set(Private_Key_File "${Trusted_Home}/private_key.pem")

set(SGX_HW ON)
if (CUSTOM_ENABLE_DEBUGING)
  set(SGX_MODE "Debug")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
else()
  set(SGX_MODE "PreRelease")
  #set(SGX_MODE "Release")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
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
"third_party/darknet/src/convolutional1D_layer.cpp"
"third_party/darknet/src/convolutional_layer.cpp"
"third_party/darknet/src/list.cpp"
"third_party/darknet/src/image.cpp"
"third_party/darknet/src/activations.cpp"
"third_party/darknet/src/col2im.cpp"
"third_party/darknet/src/blas.cpp"
"third_party/darknet/src/crop_layer.cpp"
"third_party/darknet/src/dropout_layer.cpp"
"third_party/darknet/src/maxpool_layer.cpp"
"third_party/darknet/src/maxpool1D_layer.cpp"
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
"third_party/darknet/src/avgpoolx_layer.cpp"
"third_party/darknet/src/avgpoolx1D_layer.cpp"
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
  #"third_party/darknet/src/route_layer.cpp"
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
  #"third_party/darknet/src/route_layer.cpp"
  "third_party/darknet/src/upsample_layer.cpp"
  "third_party/darknet/src/box.cpp"
  "third_party/darknet/src/normalization_layer.cpp"
  "third_party/darknet/src/local_layer.cpp"
  #"third_party/darknet/src/shortcut_layer.cpp"
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
target_include_directories(DARKNET_T PRIVATE
  "${CMAKE_SOURCE_DIR}/include"  
  "${Trusted_Home}"
  "${Trusted_Home}/include"
)
target_compile_definitions(DARKNET_T PRIVATE USE_SGX $<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING> $<$<BOOL:${CUSTOM_ENABLE_LAYERWISE}>:USE_SGX_LAYERWISE>)

set(Enclave_Cpp_Files
  #"${Trusted_Home}/src/bitonic-sort.cpp" 
  "${Trusted_Home}/src/enclave-app.cpp"
  "${Trusted_Home}/src/DNNConfigIO.cpp" 
  "${Trusted_Home}/src/DNNTrainer.cpp" 
  #"${Trusted_Home}/src/BlockHeader.cpp" 
  #"${Trusted_Home}/src/IBlockable.cpp" 
  "${Trusted_Home}/src/util.cpp" 
  #"${Trusted_Home}/src/tests.cpp"
  "${Trusted_Home}/src/SpecialBufferCommon.cpp"
  ${CMAKE_SOURCE_DIR}/src/Channel/IChannel.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWayReceiver.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWaySender.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleTwoWayChannel.cpp
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
target_compile_definitions(${Trusted_Name} PRIVATE USE_SGX $<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING> $<$<BOOL:${CUSTOM_ENABLE_LAYERWISE}>:USE_SGX_LAYERWISE>)
target_include_directories(${Trusted_Name} PRIVATE
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



# taken from https://github.com/AlexeyAB/darknet/blob/master/CMakeLists.txt
find_package(CUDA REQUIRED)
set(CUDA_LINK_LIBRARIES_KEYWORD PUBLIC)
set(CUDA_ARCHITECTURES "Auto" CACHE STRING "\"Auto\" detects local machine GPU compute arch at runtime, \"Common\" and \"All\" cover common and entire subsets of architectures, \"Names\" is a list of architectures to enable by name, \"Numbers\" is a list of compute capabilities (version number) to enable")

set_property(CACHE CUDA_ARCHITECTURES PROPERTY STRINGS "Auto" "Common" "All" "Kepler Maxwell Kepler+Tegra Maxwell+Tegra Pascal" "3.0 7.5 6.1")

cuda_select_nvcc_arch_flags(CUDA_ARCH_FLAGS ${CUDA_ARCHITECTURES})

set(ADDITIONAL_CXX_FLAGS "${ADDITIONAL_CXX_FLAGS} -DGPU")
set(CUDA_HOST_COMPILER_FLAGS "--compiler-options \" ${ADDITIONAL_CXX_FLAGS} -fPIC -fopenmp -Ofast \"")

string (REPLACE ";" " " CUDA_ARCH_FLAGS_SPACE_SEPARATED "${CUDA_ARCH_FLAGS}")
set(CMAKE_CUDA_FLAGS "${CUDA_ARCH_FLAGS_SPACE_SEPARATED} ${CUDA_HOST_COMPILER_FLAGS} ${CMAKE_CUDA_FLAGS}")
message(STATUS "CMAKE_CUDA_FLAGS: ${CMAKE_CUDA_FLAGS}")

set(DARKNET_GPU_SOURCE_FILES 
"third_party/darknet/src/convolutional_kernels.cu"
"third_party/darknet/src/deconvolutional_kernels.cu"
"third_party/darknet/src/activation_kernels.cu"
"third_party/darknet/src/im2col_kernels.cu" 
"third_party/darknet/src/col2im_kernels.cu" 
"third_party/darknet/src/blas_kernels.cu" 
"third_party/darknet/src/crop_layer_kernels.cu" 
"third_party/darknet/src/dropout_layer_kernels.cu" 
"third_party/darknet/src/maxpool_layer_kernels.cu" 
"third_party/darknet/src/avgpool_layer_kernels.cu")

add_library(DARKNET_U_GPU STATIC ${DARKNET_GPU_SOURCE_FILES} ${DARKNET_SOURCE_FILES})
set_target_properties(DARKNET_U_GPU 
                        PROPERTIES
                        CUDA_SEPERABLE_COMPILATION ON
                        POSITION_INDEPENDENT_CODE ON
                        CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_include_directories(DARKNET_U_GPU PRIVATE ${Untrusted_Home}/include  ${CUDA_INCLUDE_DIRS} ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
target_link_libraries(DARKNET_U_GPU PRIVATE curand cublas cuda)
target_compile_definitions(DARKNET_U_GPU PRIVATE)

# set(CUSTOM_GTEST_SRCS "./third_party/googletest/googletest/src/gtest-all.cc")
# set(CUSTOM_GTEST_SRCS_INCLUDE_DIR "./third_party/googletest/googletest/include" "./third_party/googletest/googletest")
# add_untrusted_library(
#   U_gtest STATIC
#   SRCS 
#     ${CUSTOM_GTEST_SRCS}
#   EDL
#     ${Trusted_Edl}
#   EDL_SEARCH_PATHS
#     ${SGX_SDK}/include
# )
# target_include_directories(U_gtest PUBLIC
#   ${CUSTOM_GTEST_SRCS_INCLUDE_DIR}
# )
# target_link_libraries(U_gtest PRIVATE Threads::Threads)

set(App_Cpp_Files
  ${Untrusted_Home}/src/app.cpp
  ${Untrusted_Home}/src/load-image.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/IRecord.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/ImageRecord.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/ImageWithLabelRecord.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/IChannel.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWayReceiver.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWaySender.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleTwoWayChannel.cpp
  )

add_untrusted_library(
  ${Untrusted_Lib_Name} SHARED
  SRCS 
    ${App_Cpp_Files}
  EDL
    ${Trusted_Edl}
  EDL_SEARCH_PATHS
    ${SGX_SDK}/include
)

target_include_directories(${Untrusted_Lib_Name} PUBLIC
"${CMAKE_SOURCE_DIR}/include"
"${Untrusted_Home}"
"${Untrusted_Home}/include"
${CUDA_INCLUDE_DIRS}
)
target_link_libraries(${Untrusted_Lib_Name} PRIVATE DARKNET_U_GPU OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

#  clang-tidy;
  #-header-filter=.;
#  -checks=*,readability-*;
set_property(TARGET ${Untrusted_Lib_Name} 
             PROPERTY 
                #CXX_CLANG_TIDY  "clang-tidy; -checks=*,readability-*;"
                CXX_CPPCHECK "cppcheck")

add_untrusted_executable(
  ${Untrusted_Name}
  SRCS 
      "${Untrusted_Home}/src/main.cpp"
  EDL
    ${Trusted_Edl}
  EDL_SEARCH_PATHS
    ${SGX_SDK}/include
)
target_link_libraries(${Untrusted_Name} PRIVATE ${Untrusted_Lib_Name})


set(TEST_SRC_FILES 
  "./test/unittests/SGXADL-tests.cpp"
  "./test/unittests/SGXADL-GeneralEnclave_test.cpp"
  "./test/unittests/Record-tests.cpp"
)
add_executable(SGXALDUnitTests ${TEST_SRC_FILES})
# set_property(TARGET SGXALDUnitTests
#              PROPERTY 
#                 #CXX_CLANG_TIDY  "clang-tidy; -checks=*,readability-*;"
#                 CXX_CPPCHECK "cppcheck; --enable=all; --std=c++14;")
target_include_directories(SGXALDUnitTests PRIVATE ${GTEST_INCLUDE_DIRS} ${SGX_INCLUDE_DIR})
target_link_libraries(SGXALDUnitTests PRIVATE ${GTEST_BOTH_LIBRARIES} ${Untrusted_Lib_Name} Threads::Threads)
add_test(gtest_unittests SGXALDUnitTests)
#set_property(TARGET SGXALDUnitTests PROPERTY CXX_CLANG_TIDY "clang-tidy; -checks=*,readability-*;")

# Just to see the generated dependencies
# add_custom_target(graphviz ALL
#     COMMAND ${CMAKE_COMMAND} "--graphviz=target_deps.dot" .
#     COMMAND dot -Tpng target_deps.dot -o target_deps.png
#     WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
# )


  