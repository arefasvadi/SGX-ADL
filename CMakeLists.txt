cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(SGX_ADL LANGUAGES C CXX CUDA)

#cmake_policy(SET CMP0069 NEW)
include(CheckIPOSupported)
check_ipo_supported(RESULT iporesult)
message(STATUS "CheckIPOSupported returns: ${iporesult}")

list(APPEND CMAKE_MODULE_PATH 
            ${CMAKE_SOURCE_DIR}/cmake)
include(Configs)
include(Utilities)

# adding google test framework
enable_testing()

if (CPPCHECK_ENABLED)
  find_package(CppCheck)
endif()

if (CLANG_TIDY_ENABLED)
  include(ClangTidy)
  enable_clang_tidy(
    CHECKS
      ${CLANG_TIDY_DEFAULT_CHECKS}
    HEADER_FILTER
        "${CMAKE_SOURCE_DIR}\/(.*\/)?.*\.h(pp)?$"
  )
endif()

if (CUSTOM_ENABLE_PURE_SGX)
  set(DARKNET_SGX_MODE PURE_SGX)
elseif(CUSTOM_ENABLE_LAYERWISE)
  set(DARKNET_SGX_MODE SGX_LAYERWISE)
elseif(CUSTOM_ENABLE_BLOCKING)
  set(DARKNET_SGX_MODE SGX_BLOCKING)
endif()

option(CUDA_VERBOSE_BUILD "Create verbose CUDA build" ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CUDA_STANDARD 14)


find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Flatbuffers REQUIRED)
find_package(Torch HINTS /usr/local/lib/python3.6/dist-packages/torch/share/cmake REQUIRED)
#find_library(SSL_LIB libssl.a REQUIRED)
#find_library(CRYPTO_LIB libcrypto.a REQUIRED)

# foonathan memory library
#add_subdirectory(third_party/memory)

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
  set(SGX_MODE Debug CACHE STRING "SGX build mode: Debug; PreRelease; Release." FORCE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
  
else()
  set(SGX_MODE PreRelease CACHE STRING "SGX build mode: Debug; PreRelease; Release." FORCE)
  #set(SGX_MODE "Release")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

message(STATUS "CUSTOM_ENABLE_DEBUGING is ${CUSTOM_ENABLE_DEBUGING}")
message(STATUS "CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")
message(STATUS "SGX_MODE is ${SGX_MODE}")


if(SGX_HW AND SGX_MODE STREQUAL "Release")
    set(LDS "${Trusted_Home}/enclave-release.lds")
    set(Trusted_Config_File "${Trusted_Home}/enclave.config.HW-Release.xml")
else()
    set(LDS "${Trusted_Home}/enclave-debug.lds")
    set(Trusted_Config_File "${Trusted_Home}/enclave.config.xml")
endif()

find_package(SGX REQUIRED)

include_directories("${PROJECT_SOURCE_DIR}/include")

#add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/blasfeo)
#message(WARNING "BLASFEO_HEADERS ${BLASFEO_HEADERS}")

set(DARKNET_SOURCE_FILES
  third_party/darknet/src/gemm.cpp
  third_party/darknet/src/utils.cpp
  third_party/darknet/src/im2col.cpp
  third_party/darknet/src/cuda.cpp
  third_party/darknet/src/deconvolutional_layer.cpp
  third_party/darknet/src/convolutional1D_layer.cpp
  third_party/darknet/src/convolutional_layer.cpp
  third_party/darknet/src/list.cpp
  third_party/darknet/src/image.cpp
  third_party/darknet/src/activations.cpp
  third_party/darknet/src/col2im.cpp
  third_party/darknet/src/blas.cpp
  third_party/darknet/src/crop_layer.cpp
  third_party/darknet/src/dropout_layer.cpp
  third_party/darknet/src/maxpool_layer.cpp
  third_party/darknet/src/maxpool1D_layer.cpp
  third_party/darknet/src/softmax_layer.cpp
  third_party/darknet/src/data.cpp
  third_party/darknet/src/matrix.cpp
  third_party/darknet/src/network.cpp
  third_party/darknet/src/connected_layer.cpp
  third_party/darknet/src/cost_layer.cpp
  third_party/darknet/src/parser.cpp
  third_party/darknet/src/option_list.cpp
  third_party/darknet/src/detection_layer.cpp
  third_party/darknet/src/route_layer.cpp
  third_party/darknet/src/upsample_layer.cpp
  third_party/darknet/src/box.cpp
  third_party/darknet/src/normalization_layer.cpp
  third_party/darknet/src/avgpool_layer.cpp
  third_party/darknet/src/avgpoolx_layer.cpp
  third_party/darknet/src/avgpoolx1D_layer.cpp
  third_party/darknet/src/layer.cpp
  third_party/darknet/src/local_layer.cpp
  third_party/darknet/src/shortcut_layer.cpp
  third_party/darknet/src/logistic_layer.cpp
  third_party/darknet/src/activation_layer.cpp
  third_party/darknet/src/rnn_layer.cpp
  third_party/darknet/src/gru_layer.cpp
  third_party/darknet/src/crnn_layer.cpp
  third_party/darknet/src/demo.cpp
  third_party/darknet/src/batchnorm_layer.cpp
  third_party/darknet/src/region_layer.cpp
  third_party/darknet/src/reorg_layer.cpp
  third_party/darknet/src/tree.cpp
  third_party/darknet/src/lstm_layer.cpp
  third_party/darknet/src/l2norm_layer.cpp
  third_party/darknet/src/yolo_layer.cpp
)

set(DARKNET_SOURCE_FILES_SGX ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_SOURCE_FILES_SGX
  third_party/darknet/src/cuda.cpp
  third_party/darknet/src/deconvolutional_layer.cpp
  third_party/darknet/src/detection_layer.cpp
  #third_party/darknet/src/route_layer.cpp
  third_party/darknet/src/upsample_layer.cpp
  third_party/darknet/src/box.cpp
  third_party/darknet/src/normalization_layer.cpp
  third_party/darknet/src/local_layer.cpp
  #third_party/darknet/src/shortcut_layer.cpp
  third_party/darknet/src/logistic_layer.cpp
  third_party/darknet/src/rnn_layer.cpp
  third_party/darknet/src/gru_layer.cpp
  third_party/darknet/src/crnn_layer.cpp
  third_party/darknet/src/demo.cpp
  third_party/darknet/src/region_layer.cpp
  third_party/darknet/src/reorg_layer.cpp
  third_party/darknet/src/tree.cpp
  third_party/darknet/src/lstm_layer.cpp
  third_party/darknet/src/l2norm_layer.cpp
  third_party/darknet/src/yolo_layer.cpp
)

set(DARKNET_SOURCE_FILES_SGX_LAYERWISE ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_SOURCE_FILES_SGX_LAYERWISE 
  third_party/darknet/src/cuda.cpp
  third_party/darknet/src/deconvolutional_layer.cpp
  third_party/darknet/src/detection_layer.cpp
  #third_party/darknet/src/route_layer.cpp
  third_party/darknet/src/upsample_layer.cpp
  third_party/darknet/src/box.cpp
  third_party/darknet/src/normalization_layer.cpp
  third_party/darknet/src/local_layer.cpp
  #third_party/darknet/src/shortcut_layer.cpp
  third_party/darknet/src/logistic_layer.cpp
  third_party/darknet/src/rnn_layer.cpp
  third_party/darknet/src/gru_layer.cpp
  third_party/darknet/src/crnn_layer.cpp
  third_party/darknet/src/demo.cpp
  third_party/darknet/src/region_layer.cpp
  third_party/darknet/src/reorg_layer.cpp
  third_party/darknet/src/tree.cpp
  third_party/darknet/src/lstm_layer.cpp
  third_party/darknet/src/l2norm_layer.cpp
  third_party/darknet/src/yolo_layer.cpp
)

set(DARKNET_SOURCE_FILES_SGX_BLOCK ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_SOURCE_FILES_SGX_BLOCK 
  third_party/darknet/src/cuda.cpp
  third_party/darknet/src/deconvolutional_layer.cpp
  third_party/darknet/src/detection_layer.cpp
  third_party/darknet/src/route_layer.cpp
  third_party/darknet/src/upsample_layer.cpp
  third_party/darknet/src/box.cpp
  #third_party/darknet/src/normalization_layer.cpp
  third_party/darknet/src/local_layer.cpp
  #third_party/darknet/src/shortcut_layer.cpp
  #third_party/darknet/src/logistic_layer.cpp
  third_party/darknet/src/rnn_layer.cpp
  third_party/darknet/src/gru_layer.cpp
  third_party/darknet/src/crnn_layer.cpp
  third_party/darknet/src/demo.cpp
  third_party/darknet/src/region_layer.cpp
  third_party/darknet/src/reorg_layer.cpp
  third_party/darknet/src/tree.cpp
  third_party/darknet/src/lstm_layer.cpp
  third_party/darknet/src/l2norm_layer.cpp
  third_party/darknet/src/yolo_layer.cpp
)

set(DARKNET_T_SOURCES)
if (CUSTOM_ENABLE_PURE_SGX)
  set(DARKNET_T_SOURCES ${DARKNET_T_SOURCES} ${DARKNET_SOURCE_FILES_SGX})
elseif(CUSTOM_ENABLE_LAYERWISE)
  set(DARKNET_T_SOURCES  ${DARKNET_T_SOURCES} ${DARKNET_SOURCE_FILES_SGX_LAYERWISE})
elseif(CUSTOM_ENABLE_BLOCKING)
  set(DARKNET_T_SOURCES  ${DARKNET_T_SOURCES} ${DARKNET_SOURCE_FILES_SGX_BLOCK})
else()
  message(FATAL "Should not be here!")
endif()

add_trusted_library(DARKNET_T 
  SRCS
  ${DARKNET_T_SOURCES}
# clang-tidy cmake script has problem with generators
#    $<$<STREQUAL:${DARKNET_SGX_MODE},PURE_SGX>:${DARKNET_SOURCE_FILES_SGX}>
#    $<$<STREQUAL:${DARKNET_SGX_MODE},SGX_LAYERWISE>:${DARKNET_SOURCE_FILES_SGX_LAYERWISE}>
#    $<$<STREQUAL:${DARKNET_SGX_MODE},>:${DARKNET_SOURCE_FILES_SGX_BLOCK}>
    ${Trusted_Home}/src/darknet-addons.cpp 
    ${Trusted_Home}/src/pcg_basic.cpp
  EDL
    ${Trusted_Edl}
  EDL_SEARCH_PATHS
    ${SGX_SDK}/include
  LDSCRIPT
    ${LDS}
)
target_include_directories(DARKNET_T PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${Trusted_Home}
  ${Trusted_Home}/include
)
set(DARKNET_T_DEFS)
if(CUSTOM_ENABLE_PURE_SGX)
  set(DARKNET_T_DEFS)
elseif(CUSTOM_ENABLE_LAYERWISE)
  set(DARKNET_T_DEFS ${DARKNET_T_DEFS} -DUSE_SGX_LAYERWISE)
elseif(CUSTOM_ENABLE_BLOCKING)
  set(DARKNET_T_DEFS ${DARKNET_T_DEFS} -DUSE_SGX_BLOCKING)
else()
  message(FATAL "Should not be here!")
endif()
target_compile_definitions(DARKNET_T PRIVATE -DUSE_SGX 
  #$<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING> $<$<BOOL:${CUSTOM_ENABLE_LAYERWISE}>:USE_SGX_LAYERWISE>
  ${DARKNET_T_DEFS}
)
attatch_clang_tidy_to_target(DARKNET_T)
#clang_tidy_check(DARKNET_T)
#clang_tidy_check_genex(DARKNET_T)

set(Enclave_Cpp_Files
  #${Trusted_Home}/src/bitonic-sort.cpp 
  ${Trusted_Home}/src/enclave-app.cpp
  ${Trusted_Home}/src/DNNConfigIO.cpp 
  ${Trusted_Home}/src/DNNTrainer.cpp
  ${Trusted_Home}/src/rand/PRNGHelper.cpp 
  #${Trusted_Home}/src/BlockHeader.cpp 
  #${Trusted_Home}/src/IBlockable.cpp 
  ${Trusted_Home}/src/util.cpp
  ${Trusted_Home}/src/extra-util.cpp
  ${CMAKE_SOURCE_DIR}/src/hexString.cpp
  #${Trusted_Home}/src/tests.cpp
  ${Trusted_Home}/src/SpecialBufferCommon.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/IChannel.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWayReceiver.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWaySender.cpp
  ${CMAKE_SOURCE_DIR}/src/Channel/SimpleTwoWayChannel.cpp

  #${CMAKE_SOURCE_DIR}/third_party/blasfeo/blas_api/sgemm.c
  )
  
# add_library(LIBXSMM_T STATIC IMPORTED)
# set_target_properties(LIBXSMM_T PROPERTIES IMPORTED_LOCATION "/home/aref/projects/libxsmm/lib/libxsmm.a")
# add_library(LIBXSMM_EXTRA_T STATIC IMPORTED)
# set_target_properties(LIBXSMM_EXTRA_T PROPERTIES IMPORTED_LOCATION "/home/aref/projects/libxsmm/lib/libxsmmext.a")

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
    #blasfeo
    #LIBXSMM_T
    #LIBXSMM_EXTRA_T
  #EXTRA_IMPORTED_LIBS
    # TODO: this is ugly!!!! needs cmake find etc.
    
  LDSCRIPT
    ${LDS}
)
target_compile_definitions(${Trusted_Name} PRIVATE -DUSE_SGX 
  #$<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING> $<$<BOOL:${CUSTOM_ENABLE_LAYERWISE}>:USE_SGX_LAYERWISE>
  ${DARKNET_T_DEFS}
)
target_include_directories(${Trusted_Name} PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  #${FLATBUFFERS_INCLUDE_DIRS}
  ${Trusted_Home}/
  ${Trusted_Home}/include
  #${CMAKE_SOURCE_DIR}/third_party/libxsmm/include
  #${CMAKE_SOURCE_DIR}/third_party/blasfeo/include
  )

#clang_tidy_check(${Trusted_Name})
attatch_clang_tidy_to_target(${Trusted_Name})

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
  third_party/darknet/src/convolutional_kernels.cu
  third_party/darknet/src/deconvolutional_kernels.cu
  third_party/darknet/src/activation_kernels.cu
  third_party/darknet/src/im2col_kernels.cu 
  third_party/darknet/src/col2im_kernels.cu 
  third_party/darknet/src/blas_kernels.cu 
  third_party/darknet/src/crop_layer_kernels.cu 
  third_party/darknet/src/dropout_layer_kernels.cu 
  third_party/darknet/src/maxpool_layer_kernels.cu 
  third_party/darknet/src/avgpool_layer_kernels.cu
)

set(DARKNET_U_SOURCE_FILES ${DARKNET_SOURCE_FILES})
list(REMOVE_ITEM DARKNET_U_SOURCE_FILES 
  #third_party/darknet/src/cuda.cpp
  third_party/darknet/src/deconvolutional_layer.cpp
  third_party/darknet/src/detection_layer.cpp
  #third_party/darknet/src/route_layer.cpp
  third_party/darknet/src/upsample_layer.cpp
  third_party/darknet/src/box.cpp
  third_party/darknet/src/normalization_layer.cpp
  third_party/darknet/src/local_layer.cpp
  #third_party/darknet/src/shortcut_layer.cpp
  third_party/darknet/src/logistic_layer.cpp
  third_party/darknet/src/rnn_layer.cpp
  third_party/darknet/src/gru_layer.cpp
  third_party/darknet/src/crnn_layer.cpp
  third_party/darknet/src/demo.cpp
  third_party/darknet/src/region_layer.cpp
  third_party/darknet/src/reorg_layer.cpp
  third_party/darknet/src/tree.cpp
  third_party/darknet/src/lstm_layer.cpp
  third_party/darknet/src/l2norm_layer.cpp
  third_party/darknet/src/yolo_layer.cpp
)

add_library(DARKNET_U_GPU SHARED ${DARKNET_GPU_SOURCE_FILES}
                                 ${DARKNET_U_SOURCE_FILES}
                                 )
set_target_properties(DARKNET_U_GPU 
                      PROPERTIES
                      #INTERPROCEDURAL_OPTIMIZATION TRUE
                      CUDA_SEPERABLE_COMPILATION ON
                      POSITION_INDEPENDENT_CODE ON
                      CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_include_directories(DARKNET_U_GPU PUBLIC ${Untrusted_Home}/include  ${CUDA_INCLUDE_DIRS} ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
target_link_libraries(DARKNET_U_GPU PRIVATE curand cublas cudart)
# ^
# |
# cuda 
# ${CUDA_LIBRARIES}
# ${CUDA_CUBLAS_LIBRARIES}
# ${CUDA_curand_LIBRARY}

target_compile_definitions(
DARKNET_U_GPU 
  PUBLIC -DGPU -DSGX_VERIFIES 
  PRIVATE -DONLY_GPU
)
#clang_tidy_check(DARKNET_U_GPU)
attatch_clang_tidy_to_target(DARKNET_U_GPU)



set(App_Cpp_Files
  ${Untrusted_Home}/src/app.cpp
  ${Untrusted_Home}/src/extras-torch.cpp
  ${Untrusted_Home}/src/load-image.cpp
  ${CMAKE_SOURCE_DIR}/src/hexString.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/IRecord.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/ImageRecord.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/ImageWithLabelRecord.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/IRecordSet.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/VectorRecordSet.cpp
  ${CMAKE_SOURCE_DIR}/src/Record/VectorRecordSetView.cpp
  #${CMAKE_SOURCE_DIR}/third_party/cryptopp-pem/pem_read.cpp
  #${CMAKE_SOURCE_DIR}/third_party/cryptopp-pem/x509cert.cpp
  #${CMAKE_SOURCE_DIR}/third_party/cryptopp-pem/pem_write.cpp
  #${CMAKE_SOURCE_DIR}/src/Channel/IChannel.cpp
  #${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWayReceiver.cpp
  #${CMAKE_SOURCE_DIR}/src/Channel/SimpleOneWaySender.cpp
  #${CMAKE_SOURCE_DIR}/src/Channel/SimpleTwoWayChannel.cpp

  # ${DARKNET_U_SOURCE_FILES}

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
${CMAKE_SOURCE_DIR}/include
${Untrusted_Home}
${Untrusted_Home}/include
${CUDA_INCLUDE_DIRS}
${TORCH_INCLUDE_DIRS}
#/usr/include/cryptopp
#${FOONATHAN_MEMORY_INCLUDE_DIR}
)
message(STATUS "CUDA_LIBRARIES: ${CUDA_LIBRARIES} CUDA_CUBLAS_LIBRARIES: ${CUDA_CUBLAS_LIBRARIES} CUDA_curand_LIBRARY: ${CUDA_curand_LIBRARY}")
target_link_libraries(${Untrusted_Lib_Name} 
PRIVATE 
  DARKNET_U_GPU
  OpenSSL::Crypto
  ${TORCH_LIBRARIES}
# OpenSSL::SSL 
# Threads::Threads  
# cryptopp
# curand 
# cublas 
# cudart
# cuda
# ${CUDA_LIBRARIES}
# ${CUDA_CUBLAS_LIBRARIES}
# ${CUDA_curand_LIBRARY}
#PUBLIC
  #foonathan_memory

)
# target_link_directories(${Untrusted_Lib_Name} PUBLIC /usr/local/cuda/lib64)
target_compile_definitions(${Untrusted_Lib_Name} PUBLIC -DGPU -DSGX_VERIFIES)
# add_dependencies(${Untrusted_Lib_Name} ${Trusted_Name})
attatch_clang_tidy_to_target(${Untrusted_Lib_Name})
#clang_tidy_check(${Untrusted_Lib_Name})


add_untrusted_executable(
  ${Untrusted_Name}
  SRCS 
      ${Untrusted_Home}/src/main.cpp
  EDL
    ${Trusted_Edl}
  EDL_SEARCH_PATHS
    ${SGX_SDK}/include
)

# add_executable(${Untrusted_Name} ${Untrusted_Home}/src/main.cpp)
# target_link_directories(${Untrusted_Name} PUBLIC /usr/local/cuda/lib64)
target_include_directories(${Untrusted_Name} PRIVATE ${Untrusted_Home}/include ${SGX_INCLUDE_DIR})
target_link_libraries(${Untrusted_Name} PRIVATE ${Untrusted_Lib_Name}
# curand 
# cublas 
# cudart
# cuda
# ${CUDA_LIBRARIES}
# ${CUDA_CUBLAS_LIBRARIES}
# ${CUDA_curand_LIBRARY}
)
attatch_clang_tidy_to_target(${Untrusted_Name})
#clang_tidy_check(${Untrusted_Name})

find_package(GTest REQUIRED)
set(TEST_SRC_FILES 
  ./test/unittests/SGXADL-tests.cpp
  ./test/unittests/SGXADL-GeneralEnclave_test.cpp
  ./test/unittests/Record-tests.cpp
  #./test/unittests/memory-pool-tests.cpp
)

# whole test section commented

# add_executable(SGXALDUnitTests ${TEST_SRC_FILES})
# target_include_directories(SGXALDUnitTests PRIVATE ${GTEST_INCLUDE_DIRS} ${SGX_INCLUDE_DIR} 
# #${FOONATHAN_MEMORY_INCLUDE_DIR}
# )
# set_target_properties(SGXALDUnitTests PROPERTIES NTERPROCEDURAL_OPTIMIZATION TRUE)
# target_compile_definitions(SGXALDUnitTests PUBLIC -DGPU -DSGX_VERIFIES)
# target_link_libraries(SGXALDUnitTests PRIVATE ${GTEST_BOTH_LIBRARIES} ${Untrusted_Lib_Name})
# attatch_clang_tidy_to_target(SGXALDUnitTests)
# #clang_tidy_check(SGXALDUnitTests)
# add_test(gtest_unittests SGXALDUnitTests)

# whole test section commented

# Just to see the generated dependencies
# add_custom_target(graphviz ALL
#     COMMAND ${CMAKE_COMMAND} "--graphviz=target_deps.dot" .
#     COMMAND dot -Tpng target_deps.dot -o target_deps.png
#     WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
# )


  