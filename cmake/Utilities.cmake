# if (CPPCHECK_ENABLED)
#     #if (NOT EXISTS ${PROJECT_BINARY_DIR}/cppcheck-out)
#     #    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/cppcheck-out)
#     #endif()
#     set(CPPCHECK_EXE 
#             cppcheck CACHE FILEPATH 
#                         "the cppcheck executable")
#     #set(CPPCHECK_OUT_DIR 
#     #        ${PROJECT_BINARY_DIR}/cppcheck-out CACHE PATH 
#     #            "Directory where the cppcheck generated output will reside")
#     #set(CPPCHECK_OPTIONS 
#     #        --enable=all CACHE STRING 
#     #            "options for cppcheck")
# endif()

# function(attach_cppcheck_to_target _target)
#     if (NOT CPPCHECK_ENABLED)
#         message(FATAL "CPPCHECK_ENABLED is ${CPPCHECK_ENABLED} so you can't add it!")
#     endif()
#     #if (NOT TARGET ${_target})
#     #    message(FATAL "the provided target := ${_target} is not a target")
#     #endif()
#     set(${_target}_cppcheck_cmd ${CPPCHECK_EXE} ${CPPCHECK_OPTIONS} --xml --output-file=${CPPCHECK_OUT_DIR}/${_target}.xml PARENT_SCOPE)
# endfunction()

# function(attatch_clang_tidy_to_target TARGET)
#     # if (NOT CLANG_TIDY_ENABLED)
#     #     message(FATAL "CLANG_TIDY_ENABLED is ${CLANG_TIDY_ENABLED} so you can't add it!")
#     # endif()
#     #if (NOT TARGET ${_target})
#     #    message(FATAL "the provided target := ${_target} is not a target")
#     #endif()
#     # get_target_property(INCLUDE_DIRECTORIES ${TARGET} INCLUDE_DIRECTORIES)
#     # get_target_property(COMPILE_OPTIONS ${TARGET} COMPILE_OPTIONS)
#     # get_target_property(COMPILE_FLAGS ${TARGET} COMPILE_FLAGS)
#     # get_target_property(COMPILE_DEFINITIONS ${TARGET} COMPILE_DEFINITIONS)
#     if (CLANG_TIDY_ENABLED)
#         string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_DEFAULT_CHECKS_STR}")
#         #string(REPLACE "$" "$$" CLANG_TIDY_HEADER_FILTER "^.*\/SGX-ADL\/.*(h|hh|hpp)$")
#         #${CMAKE_SOURCE_DIR}/.*/\(h|hpp|hh\)$$
#         set(clang_tidy_cmd clang-tidy -checks=${CLANG_TIDY_CHECKS} --header-filter=${CMAKE_SOURCE_DIR}/.*h\(pp\)?)
#         set_target_properties(${TARGET} PROPERTIES CXX_CLANG_TIDY "${clang_tidy_cmd}")
#         set_target_properties(${TARGET} PROPERTIES C_CLANG_TIDY "${clang_tidy_cmd}")
#     endif()

# endfunction()