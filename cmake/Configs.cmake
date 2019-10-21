set(CMAKE_C_COMPILER clang CACHE FILEPATH "C Compiler" FORCE)
set(CMAKE_CXX_COMPILER clang++ CACHE FILEPATH "CXX Compiler" FORCE)
#set(CMAKE_C_LINK_EXECUTABLE /usr/bin/ld.ldd CACHE FILEPATH "Linker Exe" FORCE)

set(CPPCHECK_ENABLED  OFF CACHE BOOL "Will use cppcheck to generate reports" FORCE)
set(CLANG_TIDY_ENABLED  ON CACHE BOOL "Will use clang-tidy to generate reports" FORCE)
set(INCLUDE_WHAT_YOU_USE_ENABLED OFF)
set(LINK_WHAT_YOU_USE_ENABLED ON)

set(CLANG_TIDY_DEFAULT_CHECKS_STR
    -* 
    #-clang-diagnostic-*

    performance-*
    
    #bugprone-* -bugprone-narrowing-conversions

    #cert-* 
    
    #cppcoreguidelines-* -cppcoreguidelines-avoid-magic-numbers -cppcoreguidelines-no-malloc -cppcoreguidelines-pro-bounds-pointer-arithmetic -cppcoreguidelines-pro-type-vararg
    
    #clang-analyzer-*

    #misc-*
    
    #modernize-* -modernize-use-trailing-return-type

    #google-* -google-readability-casting -google-readability-braces-around-statements

    #hicpp-* -hicpp-braces-around-statements
    
    #llvm-* -llvm-header-guard

    #fuchsia-*

    #portability-*
    
    #readability-* -readability-implicit-bool-conversion -readability-magic-numbers
    #zircorn-*
)
set(CLANG_TIDY_DEFAULT_CHECKS "${CLANG_TIDY_DEFAULT_CHECKS_STR}" CACHE STRING "Clang-tidy default checks" FORCE)
set(CPPCHECK_ERROR_EXITCODE_ARG "--error-exitcode=0" CACHE STRING "The exitcode to use if an error is found" FORCE)
set(CPPCHECK_XML_OUTPUT "${PROJECT_BINARY_DIR}/analysis/cppcheck/cppcheck-analysis.xml" CACHE STRING "" FORCE)

if (LINK_WHAT_YOU_USE_ENABLED)
    set(CMAKE_LINK_WHAT_YOU_USE ON CACHE BOOL "" FORCE)
else()
    set(CMAKE_LINK_WHAT_YOU_USE OFF CACHE BOOL "" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE CACHE BOOL "" FORCE)
set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "VERBOSITY OF BUILD" FORCE)

if (INCLUDE_WHAT_YOU_USE_ENABLED)
    set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "/home/aref/projects/iwyu/build/bin/include-what-you-use" CACHE STRING "" FORCE)
    set(CMAKE_C_INCLUDE_WHAT_YOU_USE "/home/aref/projects/iwyu/build/bin/include-what-you-use" CACHE STRING "" FORCE)
else()
    set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "" CACHE STRING "" FORCE)
    set(CMAKE_C_INCLUDE_WHAT_YOU_USE "" CACHE STRING "" FORCE)
endif()

set(CUSTOM_ENABLE_DEBUGING OFF CACHE BOOL "" FORCE)

set(CUSTOM_ENABLE_LAYERWISE ON)
#set(CUSTOM_ENABLE_BLOCKING ON)
#set(CUSTOM_ENABLE_PURE_SGX ON)