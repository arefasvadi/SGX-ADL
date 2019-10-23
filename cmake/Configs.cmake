message(STATUS "\"SGXADL_ENABLE_CLANG_COMPILER\" is ${SGXADL_ENABLE_CLANG_COMPILER}")
message(STATUS "\"CMAKE_C_COMPILER\" is ${CMAKE_C_COMPILER}")
message(STATUS "\"CMAKE_CXX_COMPILER\" is ${CMAKE_CXX_COMPILER}")


#set(CMAKE_C_LINK_EXECUTABLE /usr/bin/ld.ldd CACHE FILEPATH "Linker Exe" FORCE)

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
set(CLANG_TIDY_DEFAULT_CHECKS "${CLANG_TIDY_DEFAULT_CHECKS_STR}")

if ("${SGXADL_MODE}" MATCHES "LAYERWISE")
    set(CUSTOM_ENABLE_LAYERWISE ON)
elseif("${SGXADL_MODE}" MATCHES "PURE_SGX")
    set(CUSTOM_ENABLE_PURE_SGX ON)
elseif("${SGXADL_MODE}" MATCHES "SGX_BLOCKING")
    set(CUSTOM_ENABLE_BLOCKING ON)
    message(DEPRECATION "SGXADL_MODE is \"${SGXADL_MODE}\" -- This feature is deprecated")
else()
    message(FATAL_ERROR "\$\{\"SGXADL_MODE\"\} : ${SGXADL_MODE} cannot be set properly!")
endif()
message(STATUS "\$\{\"SGXADL_MODE\"\} : ${SGXADL_MODE}")

