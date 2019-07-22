cmake_minimum_required(VERSION 3.8)
project(SGX_DDL)

set(CUSTOM_ENABLE_BLOCKING OFF)
set(CUSTOM_ENABLE_DEBUGING ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

#set(Boost_USE_MULTITHREADED ON)
#find_package(Boost COMPONENTS system filesystem REQUIRED)
#find_package(Boost COMPONENTS thread program_options REQUIRED)

find_package(Threads REQUIRED)
find_library(SSL_LIB libssl.a REQUIRED)
find_library(CRYPTO_LIB libcrypto.a REQUIRED)

set(Untrusted_Home "${PROJECT_SOURCE_DIR}/untrusted")
set(Trusted_Home "${PROJECT_SOURCE_DIR}/trusted")
set(Scripts_Home "${PROJECT_SOURCE_DIR}/scripts")

if(NOT DEFINED ENV{SGX_SDK})
  message(FATAL "ENV Variable SGX_SDK must be set properly!")
else()
set(SGX_SDK $ENV{SGX_SDK})
message(STATUS "SDK is located at ${SGX_SDK}")
endif()

if (CUSTOM_ENABLE_DEBUGING)
  set(CMAKE_BUILD_TYPE "Debug")
  set(CUSTOM_ENCLAVE_DEFINE_FLAGS "-DDEBUG" "-UNDEBUG" "-DEDEBUG")
  set(CUSTOM_ENCLAVE_OPTM_FLAGS "-O0" "-g" "-g3" "-ggdb3")
  set(Version_Script "${Trusted_Home}/enclave-debug.lds")
  message(STATUS "project is built in debug mode")
else()
  set(CMAKE_BUILD_TYPE "Release")
  set(CUSTOM_ENCLAVE_DEFINE_FLAGS "-DNDEBUG" "-UEDEBUG" "-UDEBUG")
  set(CUSTOM_ENCLAVE_OPTM_FLAGS "-O3")
  set(Version_Script "${Trusted_Home}/enclave-release.lds")
  message(STATUS "project is built in release mode")
endif()

set(Untrusted_Name "sgxdnnapp")
set(Trusted_Name "sgxdnn.enclave.so")
set(Signed_Trusted_Name "sgxdnn.enclave.signed.so")

set(Trusted_Config_File "${Trusted_Home}/enclave.config.xml")
set(Trusted_Edl "${Trusted_Home}/enclave.edl")
set(Private_Key_File "${Trusted_Home}/private_key.pem")

set(SGX_MODE "HW")
set(SGX_ARCH "x64")
set(SGX_LIBRARY_PATH "${SGX_SDK}/lib64")
set(SGX_ENCLAVE_SIGNER "${SGX_SDK}/bin/x64/sgx_sign")
set(SGX_EDGER8R "${SGX_SDK}/bin/x64/sgx_edger8r")
set(Urts_Library_Name "sgx_urts")
set(Trts_Library_Name "sgx_trts")
set(Service_Library_Name "sgx_tservice")
set(Crypto_Library_Name "sgx_tcrypto")
set(SGX_C_STANDARD_LIBRARY_NAME "sgx_tstdc")
set(SGX_CXX_STANDARD_LIBRARY_NAME "sgx_tcxx")
set(SGX_MALLOC_LIBRARY_NAME "sgx_tcmalloc")

include_directories("${PROJECT_SOURCE_DIR}/include")

set(DEFAULT_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}" "-E")
set(DEFAULT_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}" "-E")


set(Untrusted_C_Flags "${CUSTOM_ENCLAVE_OPTM_FLAGS}" "${CUSTOM_ENCLAVE_DEFINE_FLAGS}" "-m64" "-fPIC" "-Wno-attributes")
set(Untrusted_Cpp_Flags "${Untrusted_C_Flags}")
set(Untrusted_Link_Flags "${CUSTOM_ENCLAVE_OPTM_FLAGS}" "-m64 -L${SGX_LIBRARY_PATH}")
set(Trusted_C_Flags "${CUSTOM_ENCLAVE_OPTM_FLAGS}" "-m64" "-nostdinc" "${CUSTOM_ENCLAVE_DEFINE_FLAGS}"
  "-fvisibility=hidden" "-fpie" "-fstack-protector")
set(Trusted_Cpp_Flags "${Trusted_C_Flags}" "-nostdinc++")
set(Trusted_Link_Flags "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
-Wl,--whole-archive -l${Trts_Library_Name} -Wl,--no-whole-archive \
-Wl,--whole-archive -l${SGX_MALLOC_LIBRARY_NAME} -Wl,--no-whole-archive \
-Wl,--start-group -l${SGX_C_STANDARD_LIBRARY_NAME} -l${SGX_CXX_STANDARD_LIBRARY_NAME} -l${Crypto_Library_Name} -l${Service_Library_Name} -Wl,--end-group \
-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
-Wl,--defsym,__ImageBase=0 \
-Wl,--version-script=${Version_Script}")
############################################################
set(DARKNET_SOURCE_FILES
"third_party/darknet/src/gemm.cpp"
"third_party/darknet/src/utils.cpp"
"third_party/darknet/src/im2col.cpp"
# "third_party/darknet/src/cuda.cpp"
## "third_party/darknet/src/deconvolutional_layer.cpp"
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
##"third_party/darknet/src/detection_layer.cpp"
##"third_party/darknet/src/route_layer.cpp"
##"third_party/darknet/src/upsample_layer.cpp"
# "third_party/darknet/src/box.cpp"
"third_party/darknet/src/normalization_layer.cpp"
"third_party/darknet/src/avgpool_layer.cpp"
"third_party/darknet/src/layer.cpp"
##"third_party/darknet/src/local_layer.cpp"
"third_party/darknet/src/shortcut_layer.cpp"
"third_party/darknet/src/logistic_layer.cpp"
"third_party/darknet/src/activation_layer.cpp"
##"third_party/darknet/src/rnn_layer.cpp"
##"third_party/darknet/src/gru_layer.cpp"
##"third_party/darknet/src/crnn_layer.cpp"
##"third_party/darknet/src/demo.cpp"
"third_party/darknet/src/batchnorm_layer.cpp"
# "third_party/darknet/src/region_layer.cpp"
# "third_party/darknet/src/reorg_layer.cpp"
# "third_party/darknet/src/tree.cpp"
##"third_party/darknet/src/lstm_layer.cpp"
##"third_party/darknet/src/l2norm_layer.cpp"
# "third_party/darknet/src/yolo_layer.cpp"
)
add_library(DARKNET_T OBJECT
"${DARKNET_SOURCE_FILES}"
"${Trusted_Home}/src/darknet-addons.cpp"
"${Trusted_Home}/src/pcg_basic.c"
)
#SET_SOURCE_FILES_PROPERTIES(${DARKNET_SOURCE_FILES} PROPERTIES LANGUAGE CXX )

target_include_directories(DARKNET_T PUBLIC
  "${Trusted_Home}"
  "${Trusted_Home}/include"
  "${SGX_SDK}/include"
  "${SGX_SDK}/include/tlibc"
  #"${SGX_SDK}/include/stdc++"
  "${SGX_SDK}/include/libcxx"
)
target_compile_options(DARKNET_T PUBLIC 
"${Trusted_Cpp_Flags}"
)
target_compile_definitions(DARKNET_T PUBLIC USE_SGX $<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING>)
########################################################################################################################
#Untrusted Code
execute_process(COMMAND "${SGX_EDGER8R}"
  "--untrusted"
  "${Trusted_Edl}"
  "--search-path"
  "${SGX_SDK}/include"
  WORKING_DIRECTORY "${Untrusted_Home}"
  RESULT_VARIABLE SGX_EDGER8R_RES
  ERROR_VARIABLE SGX_EDGER8R_ERROR_UNTRUSTED
  )

if (NOT ${SGX_EDGER8R_RES} MATCHES "0")
  MESSAGE(FATAL_ERROR "Edger8r Not worked for untrusted site! ${SGX_EDGER8R_ERROR_UNTRUSTED}")
else()
  MESSAGE(STATUS "Generated untrusted bridges")
endif ()

file(GLOB Untrusted_C_Files "${Untrusted_Home}/*_u.c")
add_library(Enclave_U OBJECT "${Untrusted_C_Files}")
target_include_directories(Enclave_U PUBLIC "${Untrusted_Home}" "${Untrusted_Home}/include" "${SGX_SDK}/include")
target_compile_options(Enclave_U PUBLIC "${Untrusted_C_Flags}")

########################################################################################################################
#Trusted Code
execute_process(COMMAND "${SGX_EDGER8R}"
  "--trusted"
  "${Trusted_Edl}"
  "--search-path"
  "${SGX_SDK}/include"
  WORKING_DIRECTORY "${Trusted_Home}"
  RESULT_VARIABLE SGX_EDGER8R_RES
  ERROR_VARIABLE SGX_EDGER8R_ERROR_TRUSTED)
if (NOT ${SGX_EDGER8R_RES} MATCHES "0")
  MESSAGE(FATAL_ERROR "Edger8r Not worked for trusted site! ${SGX_EDGER8R_ERROR_TRUSTED}")
else()
  MESSAGE(STATUS "Generated trusted bridges")
endif ()

file(GLOB Trusdted_C_Files "${Trusted_Home}/*_t.c")
add_library(Enclave_T OBJECT "${Trusdted_C_Files}")
target_include_directories(Enclave_T PUBLIC
  "${Trusted_Home}"
  "${Trusted_Home}/include"
  "${SGX_SDK}/include"
  "${SGX_SDK}/include/tlibc"
  # "${SGX_SDK}/include/stlport" # maybe need to be uncommented!
  # "${SGX_SDK}/include/stdc++"
   "${SGX_SDK}/include/libcxx"
  )
target_compile_options(Enclave_T PUBLIC "${Trusted_C_Flags}")

########################################################################################################################
#Untrusted Code
# file(GLOB App_Cpp_Files "${Untrusted_Home}/src/*.cpp" "${Untrusted_Home}/UTHeaders/*.h" "${Untrusted_Home}/*.h")
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
add_executable(${Untrusted_Name} "${App_Cpp_Files}" $<TARGET_OBJECTS:Enclave_U>)
target_include_directories(${Untrusted_Name} PUBLIC
  "${CMAKE_SOURCE_DIR}/include"
  "${Untrusted_Home}"
  "${Untrusted_Home}/include"
  "third_party/darknet/include"
  "${SGX_SDK}/include")

target_compile_options(${Untrusted_Name} PUBLIC "${Untrusted_Cpp_Flags}" "-msse4.2")
MESSAGE(STATUS "${Untrusted_Name}")
set_target_properties(${Untrusted_Name} PROPERTIES LINK_FLAGS "${Untrusted_Link_Flags}")
target_link_libraries(${Untrusted_Name} ${Urts_Library_Name} "crypto" "pthread" "sgx_uae_service")
########################################################################################################################
#Trusted Code
# file(GLOB Enclave_Cpp_Files "${Trusted_Home}/src/*.cpp"
#   "${Trusted_Home}/THeaders/*.h" "${Trusted_Home}/*.h"
#   )
set(Enclave_Cpp_Files
  "${Trusted_Home}/src/bitonic-sort.cpp" 
  "${Trusted_Home}/src/enclave-app.cpp"
  "${Trusted_Home}/src/DNNConfigIO.cpp" 
  "${Trusted_Home}/src/DNNTrainer.cpp" 
  "${Trusted_Home}/src/BlockHeader.cpp" 
  "${Trusted_Home}/src/IBlockable.cpp" 
  "${Trusted_Home}/src/util.cpp" 
  "${Trusted_Home}/src/tests.cpp"
  )
add_executable(${Trusted_Name} "${Enclave_Cpp_Files}" $<TARGET_OBJECTS:Enclave_T> $<TARGET_OBJECTS:DARKNET_T>)
target_include_directories(${Trusted_Name} PUBLIC
  "${CMAKE_SOURCE_DIR}/include"
  "${Trusted_Home}/"
  "${Trusted_Home}/include"
  "${SGX_SDK}/include"
  "${SGX_SDK}/include/tlibc"
   #"${SGX_SDK}/include/stlport"
   #"${SGX_SDK}/include/stdc++"
  "${SGX_SDK}/include/libcxx"
  )
target_compile_options(${Trusted_Name} PUBLIC "${Trusted_Cpp_Flags}")
target_compile_definitions(${Trusted_Name} PUBLIC USE_SGX $<$<BOOL:${CUSTOM_ENABLE_BLOCKING}>:USE_SGX_BLOCKING>)

target_link_libraries(${Trusted_Name} "${Trusted_Link_Flags}")
if (CMAKE_BUILD_TYPE MATCHES "Debug")
  set_target_properties(${Trusted_Name} PROPERTIES LINK_FLAGS "-O0 -g -m64 -ggdb3")
else()
  set_target_properties(${Trusted_Name} PROPERTIES LINK_FLAGS "-O3 -m64")
endif()
add_custom_command(OUTPUT ${Signed_Trusted_Name}
  COMMAND ${SGX_ENCLAVE_SIGNER} "sign" "-key" "${Private_Key_File}" "-enclave" "${PROJECT_BINARY_DIR}/${Trusted_Name}" "-out" "${PROJECT_BINARY_DIR}/${Signed_Trusted_Name}" "-config" "${Trusted_Config_File}"
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  DEPENDS ${Trusted_Name}
  VERBATIM
  USES_TERMINAL)
add_custom_target(sign ALL DEPENDS ${Signed_Trusted_Name} ${Untrusted_Name})
########################################################################################################################
