# downloaded from https://github.com/zhang-xin/SGX-CMake/blob/master/cmake/FindSGX.cmake <- THANKS
# and made some changes for my own use
# FindPackage cmake file for Intel SGX SDK

cmake_minimum_required(VERSION 3.15)
include(CMakeParseArguments)

set(SGX_FOUND "NO")

if(EXISTS SGX_DIR)
    set(SGX_PATH ${SGX_DIR})
elseif(EXISTS SGX_ROOT)
    set(SGX_PATH ${SGX_DIR})
elseif(EXISTS $ENV{SGX_SDK})
    set(SGX_PATH $ENV{SGX_SDK})
elseif(EXISTS $ENV{SGX_DIR})
    set(SGX_PATH $ENV{SGX_DIR})
elseif(EXISTS $ENV{SGX_ROOT})
    set(SGX_PATH $ENV{SGX_ROOT})
else()
    message(WARNING "Using default path /opt/intel/sgxsdk")
    set(SGX_PATH "/opt/intel/sgxsdk")
endif()

message(STATUS "the found sgx-sdk root dir is ${SGX_PATH}")
# SGX_COMMON_CFLAGS
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SGX_COMMON_FLAGS -m32)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib32)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x86/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x86/sgx_edger8r)
else()
    # -fopenmp
    set(SGX_COMMON_FLAGS "-march=native -m64 -mavx -mavx2 -mssse3 -msse3 -msse4.1 -msse4.2 -msse4a -fopenmp")
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib64)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x64/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x64/sgx_edger8r)
endif()

find_path(SGX_INCLUDE_DIR sgx.h "${SGX_PATH}/include" NO_DEFAULT_PATH)
find_path(SGX_LIBRARY_DIR libsgx_urts.so "${SGX_LIBRARY_PATH}" NO_DEFAULT_PATH)

if(SGX_INCLUDE_DIR AND SGX_LIBRARY_DIR)
    set(SGX_FOUND "YES")
    set(SGX_INCLUDE_DIR "${SGX_PATH}/include" CACHE PATH "Intel SGX include directory" FORCE)
    set(SGX_TLIBC_INCLUDE_DIR "${SGX_INCLUDE_DIR}/tlibc" CACHE PATH "Intel SGX tlibc include directory" FORCE)
    set(SGX_LIBCXX_INCLUDE_DIR "${SGX_INCLUDE_DIR}/libcxx" CACHE PATH "Intel SGX libcxx include directory" FORCE)
    # set(SGX_INTRINSICS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include/ported-intrinsics CACHE PATH "ported intrinsics from clang 9.0" FORCE)
    set(SGX_INCLUDE_DIRS ${SGX_INCLUDE_DIR} ${SGX_TLIBC_INCLUDE_DIR} ${SGX_LIBCXX_INCLUDE_DIR} 
        # ${SGX_INTRINSICS_INCLUDE_DIR}
        )
    mark_as_advanced(SGX_INCLUDE_DIR SGX_TLIBC_INCLUDE_DIR SGX_LIBCXX_INCLUDE_DIR SGX_LIBRARY_DIR 
        # SGX_INTRINSICS_INCLUDE_DIR
        )
    message(STATUS "Found Intel SGX SDK.")
endif()

if(SGX_FOUND)
    set(SGX_HW ON CACHE BOOL "Run SGX on hardware, OFF for simulation.")
    set(SGX_MODE PreRelease CACHE STRING "SGX build mode: Debug; PreRelease; Release.")
    set(SGX_SWITCHLESS_LIB sgx_tswitchless)
    set(SGX_USWITCHLESS_LIB sgx_uswitchless)
    if(SGX_HW)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else()
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
    endif()

    if(SGX_MODE STREQUAL "Debug")
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS}  -O0 -g -g3 -ggdb -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(SGX_MODE STREQUAL "PreRelease")
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS}  -O3 -UDEBUG -DNDEBUG -DEDEBUG")
    elseif(SGX_MODE STREQUAL "Release")
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS}  -O3 -UDEBUG -DNDEBUG -UEDEBUG")
    else()
        message(FATAL_ERROR "SGX_MODE ${SGX_MODE} is not Debug, PreRelease or Release.")
    endif()

    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} \
        -Wall -Wextra -Wpedantic -Winit-self -Wpointer-arith -Wreturn-type \
        -Waddress -Wsequence-point -Wformat-security \
        -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
        -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls")

    set(SGX_COMMON_CFLAGS "${SGX_COMMON_FLAGS} -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants")
    set(SGX_COMMON_CXXFLAGS "${SGX_COMMON_FLAGS} -Wnon-virtual-dtor")

    # set(ENCLAVE_INC_FLAGS "-I${SGX_INCLUDE_DIR} -I${SGX_TLIBC_INCLUDE_DIR} -I${SGX_LIBCXX_INCLUDE_DIR} -I${SGX_INTRINSICS_INCLUDE_DIR}")
    set(ENCLAVE_INC_FLAGS "-I${SGX_INCLUDE_DIR} -I${SGX_TLIBC_INCLUDE_DIR} -I${SGX_LIBCXX_INCLUDE_DIR}")
    set(ENCLAVE_C_FLAGS "${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong ${ENCLAVE_INC_FLAGS}")
    set(ENCLAVE_CXX_FLAGS "${SGX_COMMON_CXXFLAGS} -nostdinc++ -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong ${ENCLAVE_INC_FLAGS}")

    set(APP_INC_FLAGS "-I${SGX_INCLUDE_DIR}")
    set(APP_C_FLAGS "${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes ${APP_INC_FLAGS}")
    set(APP_CXX_FLAGS "${SGX_COMMON_CXXFLAGS} -fPIC -Wno-attributes ${APP_INC_FLAGS}")

    function(_build_edl_obj edl edl_search_paths use_prefix)
        get_filename_component(EDL_NAME ${edl} NAME_WE)
        get_filename_component(EDL_ABSPATH ${edl} ABSOLUTE)
        set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
        set(SEARCH_PATHS "")
        foreach(path ${edl_search_paths})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
        if(${use_prefix})
            set(USE_PREFIX "--use-prefix")
        endif()
        add_custom_command(OUTPUT ${EDL_T_C}
                           COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        # message(FATAL_ERROR "THE EDL FILE IS ${EDL_T_C}")

        add_library(${target}-edlobj OBJECT ${EDL_T_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS}
                                                          INTERPROCEDURAL_OPTIMIZATION TRUE
                                                          POSITION_INDEPENDENT_CODE ON)
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")
    endfunction()

    # build trusted static library to be linked into enclave library
    function(add_trusted_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file search paths are not provided!")
        endif()
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()

        _build_edl_obj(${SGX_EDL} ${SGX_EDL_SEARCH_PATHS} ${SGX_USE_PREFIX})

        add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS}
                                                    INTERPROCEDURAL_OPTIMIZATION TRUE)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        # ${SGX_COMMON_CFLAGS} \
        # -lsgx_pthread -lsgx_omp -lsgx_dnnl
        target_link_libraries(${target} PRIVATE "${SGX_COMMON_CFLAGS} \ 
            -Wl,-z,relro,-z,now,-z,noexecstack \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_SWITCHLESS_LIB} -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--whole-archive -lsgx_tcmalloc -Wl,--no-whole-archive \
            -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections --verbose")
    endfunction()

    # build enclave shared library
    function(add_enclave_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        #set(multiValueArgs SRCS TRUSTED_LIBS EXTRA_IMPORTED_LIBS EDL_SEARCH_PATHS)
        set(multiValueArgs SRCS TRUSTED_LIBS EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file search paths are not provided!")
        endif()
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()

        _build_edl_obj(${SGX_EDL} ${SGX_EDL_SEARCH_PATHS} ${SGX_USE_PREFIX})

        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS}
                                                    INTERPROCEDURAL_OPTIMIZATION TRUE
                                                    POSITION_INDEPENDENT_CODE ON)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

        set(TLIB_LIST "")
        foreach(TLIB ${SGX_TRUSTED_LIBS})
            string(APPEND TLIB_LIST "$<TARGET_FILE:${TLIB}> ")
            add_dependencies(${target} ${TLIB})
        endforeach()
        
        # set(EXTLIB_LIST "")
        # foreach(EXTLIB ${EXTRA_IMPORTED_LIBS})
        #     string(APPEND EXTLIB_LIST ${EXTLIB})
        #     add_dependencies(${target} ${EXTLIB})
        # endforeach()
        # ${SGX_COMMON_CFLAGS} \

        # -lsgx_pthread -lsgx_omp -lsgx_dnnl -lsgx_blasfeo
        target_link_libraries(${target} PRIVATE "${SGX_COMMON_CFLAGS} \
            -Wl,-z,relro,-z,now,-z,noexecstack \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_SWITCHLESS_LIB} -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--whole-archive -lsgx_tcmalloc -Wl,--no-whole-archive \
            -Wl,--start-group ${TLIB_LIST} -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_omp -lsgx_dnnl -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections --verbose")
    endfunction()

    # sign the enclave, according to configurations one-step or two-step signing will be performed.
    # default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
    function(enclave_sign target)
        set(oneValueArgs KEY CONFIG OUTPUT)
        cmake_parse_arguments("SGX" "" "${oneValueArgs}" "" ${ARGN})
        if("${SGX_CONFIG}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave config is not provided!")
        endif()
        if("${SGX_KEY}" STREQUAL "")
            if (NOT SGX_HW OR NOT SGX_MODE STREQUAL "Release")
                message(FATAL_ERROR "Private key used to sign enclave is not provided!")
            endif()
        else()
            get_filename_component(KEY_ABSPATH ${SGX_KEY} ABSOLUTE)
        endif()
        if("${SGX_OUTPUT}" STREQUAL "")
            set(OUTPUT_NAME "${target}.signed.so")
        else()
            set(OUTPUT_NAME ${SGX_OUTPUT})
        endif()

        get_filename_component(CONFIG_ABSPATH ${SGX_CONFIG} ABSOLUTE)

        if(SGX_HW AND SGX_MODE STREQUAL "Release")
            add_custom_target(${target}-sign ALL
                              COMMAND ${SGX_ENCLAVE_SIGNER} gendata -config ${CONFIG_ABSPATH}
                                      -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${target}_hash.hex
                              COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                                  --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/${target}_hash.hex for second step"
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        else()
            add_custom_target(${target}-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${KEY_ABSPATH} -config ${CONFIG_ABSPATH}
                              -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME}
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        endif()

        set(CLEAN_FILES "$<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME};$<TARGET_FILE_DIR:${target}>/${target}_hash.hex")
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")
    endfunction()

    function(add_untrusted_library target mode)
        set(optionArgs USE_PREFIX)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file search paths are not provided!")
        endif()

        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

            list(APPEND EDL_U_SRCS ${EDL_U_C})
        endforeach()

        add_library(${target} ${mode} ${SGX_SRCS} ${EDL_U_SRCS})
        
        # target_compile_options(${target} PRIVATE "${APP_CXX_FLAGS}")
        # set_target_properties(${target} PROPERTIES 
        #     INTERPROCEDURAL_OPTIMIZATION TRUE
        # )
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS}
                                        INTERPROCEDURAL_OPTIMIZATION TRUE
                                        POSITION_INDEPENDENT_CODE ON)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        # ${SGX_COMMON_CFLAGS} \
        #  -l${SGX_USVC_LIB} \
        #  -lsgx_ukey_exchange \
        #-Wl,--whole-archive  -l${SGX_USWITCHLESS_LIB} -Wl,--no-whole-archive \

        target_link_libraries(${target} PRIVATE "-L${SGX_LIBRARY_PATH} \
                                         -l${SGX_URTS_LIB} \
                                         -lpthread \
                                         -l${SGX_USVC_LIB}")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

    function(add_untrusted_executable target)
        set(optionArgs USE_PREFIX)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message(FATAL_ERROR "SGX enclave edl file search paths are not provided!")
        endif()

        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

            list(APPEND EDL_U_SRCS ${EDL_U_C})
        endforeach()

        add_executable(${target} ${SGX_SRCS} ${EDL_U_SRCS})

        # target_compile_options(${target} PRIVATE "${APP_CXX_FLAGS}")
        # set_target_properties(${target} PROPERTIES 
        #     INTERPROCEDURAL_OPTIMIZATION TRUE
        # )

        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS}
                                        INTERPROCEDURAL_OPTIMIZATION TRUE
                                        POSITION_INDEPENDENT_CODE ON)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
        # ${SGX_COMMON_CFLAGS} \
        #  -l${SGX_USVC_LIB} \
        #  -lsgx_ukey_exchange \
        #-Wl,--whole-archive  -l${SGX_USWITCHLESS_LIB} -Wl,--no-whole-archive \

        target_link_libraries(${target} PRIVATE "-L${SGX_LIBRARY_PATH} \
                                         -l${SGX_URTS_LIB} \
                                         -Wl,--whole-archive  -l${SGX_USWITCHLESS_LIB} -Wl,--no-whole-archive \
                                         -lpthread \
                                         -l${SGX_USVC_LIB}")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

else(SGX_FOUND)
    message(WARNING "Intel SGX SDK not found!")
    if(SGX_FIND_REQUIRED)
        message(FATAL_ERROR "Could NOT find Intel SGX SDK!")
    endif()
endif(SGX_FOUND)
