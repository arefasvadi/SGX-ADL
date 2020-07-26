#!/bin/bash
#TODO: Add get opts
SCRIPT_ROOT="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SRC_ROOT="$(dirname "${SCRIPT_ROOT}")"
BUILD_ROOT="${SRC_ROOT}/build"
BUILD_GEN="Ninja"
SGXADL_MODE="LAYERWISE"

check_project_valid() {
    echo "script root directory \"${SCRIPT_ROOT}\""
    echo "project root directory \"${SRC_ROOT}\""
    if [ "$SGX_SDK" = "" ]
    then
        echo "environment variable SGX_SDK not set!"
        exit 1
    else
        echo "sourcing SGX_SDK/environment"
        source "$SGX_SDK/environment"
    fi
}

create_new_build_dir() {
    mkdir -p "${BUILD_ROOT}"
    echo "created build directory ${BUILD_ROOT}"
    rm -rf "${BUILD_ROOT}/*"
    echo "removed contentes of build directory ${BUILD_ROOT}"
}

configure_cmake() {
    pushd "${BUILD_ROOT}"
    cmake -G "${BUILD_GEN}" -DSGXADL_MODE=${SGXADL_MODE} -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ../
    echo "Going back to the directory where script was called"
    echo "Now go to ${BUILD_ROOT} and build the project"
    popd
}

check_project_valid

create_new_build_dir

configure_cmake




