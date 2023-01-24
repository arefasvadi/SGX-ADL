# set(SGXADL_ENABLE_CLANG_COMPILER ON CACHE BOOL "Use clang as c,cxx compiler")
#set(FLATBUFFERS_INCLUDE_DIRS "/usr/local/include/" CACHE STRING "Flatbuffer include directory")
set(SGXADL_CPPCHECK_ENABLED  OFF CACHE BOOL "Will use cppcheck to generate reports")
set(SGXADL_CLANG_TIDY_ENABLED  OFF CACHE BOOL "Will use clang-tidy to generate reports")
set(SGXADL_INCLUDE_WHAT_YOU_USE_ENABLED OFF CACHE BOOL "")
set(SGXADL_LINK_WHAT_YOU_USE_ENABLED ON CACHE BOOL "")

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE CACHE BOOL "")
set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "ON")

set(CPPCHECK_ERROR_EXITCODE_ARG "--error-exitcode=0" CACHE STRING "The exitcode to use if an error is found")
set(CPPCHECK_XML_OUTPUT "${PROJECT_BINARY_DIR}/analysis/cppcheck/cppcheck-analysis.xml" CACHE STRING "")

set(CUSTOM_ENABLE_DEBUGING OFF CACHE BOOL "")
set(SGXADL_MODE "LAYERWISE" CACHE STRING "PURE_SGX, LAYERWISE, SGX_BLOCKING")

if (SGXADL_ENABLE_CLANG_COMPILER)
    set(CMAKE_C_COMPILER clang CACHE FILEPATH "C Compiler")
    set(CMAKE_CXX_COMPILER clang++ CACHE FILEPATH "CXX Compiler")
endif()

if (SGXADL_LINK_WHAT_YOU_USE_ENABLED)
    set(CMAKE_LINK_WHAT_YOU_USE ON CACHE BOOL "")
else()
    set(CMAKE_LINK_WHAT_YOU_USE OFF CACHE BOOL "")
endif()

if (SGXADL_INCLUDE_WHAT_YOU_USE_ENABLED)
    set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "/home/aref/projects/iwyu/build/bin/include-what-you-use" CACHE STRING "")
    set(CMAKE_C_INCLUDE_WHAT_YOU_USE "/home/aref/projects/iwyu/build/bin/include-what-you-use" CACHE STRING "")
else()
    set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "" CACHE STRING "")
    set(CMAKE_C_INCLUDE_WHAT_YOU_USE "" CACHE STRING "")
endif()



