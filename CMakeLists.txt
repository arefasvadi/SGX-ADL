cmake_minimum_required(VERSION 3.5)
project(SGX_DDL)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 14)

set(Boost_USE_MULTITHREADED ON)
find_package(Boost COMPONENTS system filesystem REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost COMPONENTS thread program_options REQUIRED)
find_library(SSL_LIB libssl.a REQUIRED)
find_library(CRYPTO_LIB libcrypto.a REQUIRED)

set(Untrusted_Home "${PROJECT_SOURCE_DIR}/untrusted")
set(Trusted_Home "${PROJECT_SOURCE_DIR}/trusted")
set(Scripts_Home "${PROJECT_SOURCE_DIR}/scripts")

set(Untrusted_Name "sgxdnnapp")
set(Trusted_Name "sgxdnn.enclave.so")
set(Signed_Trusted_Name "sgxdnn.enclave.signed.so")
set(Trusted_Config_File "${Trusted_Home}/enclave.config.xml")
set(Trusted_Edl "${Trusted_Home}/enclave.edl")
set(Private_Key_File "${Trusted_Home}/enclave_private.pem")
set(Version_Script "${Trusted_Home}/enclave.lds")

#set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_SDK "/opt/intel/sgx-2.2/sgxsdk")
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

# include_directories("${PROJECT_SOURCE_DIR}/third_party/darknet/include")

set(DEFAULT_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
set(DEFAULT_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
if (CMAKE_BUILD_TYPE MATCHES "Debug")
  set(Untrusted_C_Flags "-O0" "-g3" "-m64"
    "-fPIC" "-Wno-attributes" "-DDEBUG" "-UNDEBUG" "-UEDEBUG")
  set(Untrusted_Cpp_Flags "${Untrusted_C_Flags}" "-std=c++14")
  set(Untrusted_Link_Flags "-O0 -g3 -m64 -L${SGX_LIBRARY_PATH}")
  set(Trusted_C_Flags "-O0" "-g3" "-m64" "-nostdinc"
    "-fvisibility=hidden" "-fpie" "-fstack-protector")
else()
  set(Untrusted_C_Flags "-O3" "-g0" "-m64"
    "-fPIC" "-Wno-attributes"
    "-DDEBUG" "-UNDEBUG" "-UEDEBUG"
#    "-DNDEBUG" "-UEDEBUG" "-UDEBUG"
    )
  set(Untrusted_Cpp_Flags "${Untrusted_C_Flags}" "-std=c++11")
  set(Untrusted_Link_Flags "-O3 -g0 -m64 -L${SGX_LIBRARY_PATH}")
  set(Trusted_C_Flags "-O3" "-g0" "-m64" "-nostdinc"
    "-fvisibility=hidden" "-fpie" "-fstack-protector")
endif()

set(Trusted_C_Flags "-O3" "-g" "-m64" "-nostdinc"
  "-fvisibility=hidden" "-fpie" "-fstack-protector")
set(Trusted_Cpp_Flags "${Trusted_C_Flags}" "-std=c++14" "-nostdinc++")
set(Trusted_Link_Flags "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
-Wl,--whole-archive -l${Trts_Library_Name} -Wl,--no-whole-archive \
-Wl,--start-group -l${SGX_C_STANDARD_LIBRARY_NAME} -l${SGX_CXX_STANDARD_LIBRARY_NAME} -l${Crypto_Library_Name} -l${Service_Library_Name} -Wl,--end-group \
-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
-Wl,--defsym,__ImageBase=0 \
-Wl,--version-script=${Version_Script}")

########################################################################################################################
#Untrusted Code
execute_process(COMMAND "${SGX_EDGER8R}"
  "--untrusted"
  "${Trusted_Edl}"
  #        "--search-path"
  #        "${SGX_SDK}/include"
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
  #        "--search-path"
  #        "${SGX_SDK}/include"
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
  # "${SGX_SDK}/include/libcxx"
  )
target_compile_options(Enclave_T PUBLIC "${Trusted_C_Flags}")

########################################################################################################################
#Untrusted Code
# file(GLOB App_Cpp_Files "${Untrusted_Home}/src/*.cpp" "${Untrusted_Home}/UTHeaders/*.h" "${Untrusted_Home}/*.h")
set(App_Cpp_Files "${Untrusted_Home}/src/app.cpp")
add_executable(${Untrusted_Name} "${App_Cpp_Files}" $<TARGET_OBJECTS:Enclave_U>)
target_include_directories(${Untrusted_Name} PUBLIC
  "${Untrusted_Home}"
  "${Untrusted_Home}/include"
  "${SGX_SDK}/include")
target_compile_options(${Untrusted_Name} PUBLIC "${Untrusted_Cpp_Flags}" "-msse4.2")
set_target_properties(${Untrusted_Name} PROPERTIES LINK_FLAGS "${Untrusted_Link_Flags}")
target_link_libraries(${Untrusted_Name} ${Urts_Library_Name} "pthread" "sgx_uae_service")
########################################################################################################################
#Trusted Code
# file(GLOB Enclave_Cpp_Files "${Trusted_Home}/src/*.cpp"
#   "${Trusted_Home}/THeaders/*.h" "${Trusted_Home}/*.h"
#   )
set(Enclave_Cpp_Files "${Trusted_Home}/src/enclave-app.cpp"
  "${Trusted_Home}/src/DNNConfigIO.cpp" 
  "${Trusted_Home}/src/DNNTrainer.cpp" 
  )
add_executable(${Trusted_Name} "${Enclave_Cpp_Files}" $<TARGET_OBJECTS:Enclave_T>)
target_include_directories(${Trusted_Name} PUBLIC
  "${Trusted_Home}/"
  "${Trusted_Home}/include"
  "${SGX_SDK}/include"
  "${SGX_SDK}/include/tlibc"
  # "${SGX_SDK}/include/stlport"
  # "${SGX_SDK}/include/stdc++"
  "${SGX_SDK}/include/libcxx")
target_compile_options(${Trusted_Name} PUBLIC "${Trusted_Cpp_Flags}")
#target_link_libraries(${Trusted_Name} "/usr/lib/x86_64-linux-gnu/libgsl.a" "/usr/lib/x86_64-linux-gnu/libgslcblas.a" "${Trusted_Link_Flags}")
target_link_libraries(${Trusted_Name} "${Trusted_Link_Flags}")
if (CMAKE_BUILD_TYPE MATCHES "Debug")
  set_target_properties(${Trusted_Name} PROPERTIES LINK_FLAGS "-O0 -g3 -m64")
else()
  set_target_properties(${Trusted_Name} PROPERTIES LINK_FLAGS "-O3 -g -m64")
endif()
add_custom_command(OUTPUT ${Signed_Trusted_Name}
  COMMAND ${SGX_ENCLAVE_SIGNER} "sign" "-key" "${Private_Key_File}" "-enclave" "${PROJECT_BINARY_DIR}/${Trusted_Name}" "-out" "${PROJECT_BINARY_DIR}/${Signed_Trusted_Name}" "-config" "${Trusted_Config_File}"
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  DEPENDS ${Trusted_Name}
  VERBATIM
  USES_TERMINAL)
add_custom_target(sign ALL DEPENDS ${Signed_Trusted_Name} ${Untrusted_Name})
########################################################################################################################
