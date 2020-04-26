# Copyright (C) 2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

ARG ARG_SGX_SDK=/opt/intel/sgxsdk
ARG USERNAME=aref
ARG USER_UID=1000
ARG USER_GID=${USER_UID}

FROM ubuntu:18.04 as builder

ARG USERNAME
ARG USER_UID
ARG USER_GID
ARG ARG_SGX_SDK

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

RUN apt-get update && apt-get install  -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    curl \
    debhelper \
    git \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    lsb-release \
    ocaml \
    ocamlbuild \
    protobuf-compiler \
    python \
    wget

# We assume this docker file is invoked with root at the top of linux-sgx repo, see shell scripts for example.

WORKDIR /linux-sgx
COPY . .
RUN chown -R ${USERNAME}:${USER_GID} .
USER ${USERNAME}

RUN ./download_prebuilt.sh && make -j8 sdk_install_pkg_no_mitigation
RUN git config --global user.email "root@abc.com" && git config --global user.name "root" && cd external/dnnl && make -j8

WORKDIR /opt/intel
ENV SGX_SDK=${ARG_SGX_SDK}
RUN sudo sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'
RUN sudo cp /linux-sgx/external/dnnl/sgx_dnnl/lib/libsgx_dnnl.a ${ARG_SGX_SDK}/lib64 \
    && sudo cp /linux-sgx/external/dnnl/sgx_dnnl/include/* ${ARG_SGX_SDK}/include/

WORKDIR /linux-sgx
RUN make -j8 psw_install_pkg


FROM ubuntu:18.04 as aesm
ARG USERNAME
ARG USER_UID
ARG USER_GID
ARG ARG_SGX_SDK

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

RUN apt-get update && apt-get install -y \
    libcurl4 \
    libprotobuf10 \
    libssl1.1 \
    make \
    module-init-tools

WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
#USER aesmd
USER ${USERNAME}
WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon


FROM nvidia/cuda:10.0-cudnn7-devel-ubuntu18.04 as DevSGXADL

ARG USERNAME
ARG USER_UID
ARG USER_GID
ARG ARG_SGX_SDK

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo wget g++ make build-essential\
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

RUN wget https://github.com/Kitware/CMake/releases/download/v3.15.2/cmake-3.15.2.tar.gz && \
    tar -zxvf cmake-3.15.2.tar.gz && \
    cd cmake-3.15.2 && ./bootstrap && make -j8 && make install \
    && cd .. && rm -rf cmake-3.15.2*

RUN apt-get update && apt-get install -y \
      git libncurses-dev zlib1g-dev \
      libevent-dev \
      python python-pip \
      python3 python3-pip\
      gdb curl \
      libcurl4-openssl-dev \
      libprotobuf-dev \
      libssl-dev \
      ninja-build \
      module-init-tools \
      clang-9 libclang-9-dev clang-tools-9 llvm-9 libclang-common-9-dev zlib1g-dev git \
      libcrypto++6 libcrypto++6-dbg libcrypto++-dev \
	  && git clone --depth=1 --recursive https://github.com/MaskRay/ccls \
	  && cd ccls \
	  && wget -c http://releases.llvm.org/8.0.0/clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
	  && tar xf clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
	  && cmake -H. -BRelease -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$PWD/clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04 \
	  && cmake --build Release && ln -s /ccls/Release/ccls /usr/bin/ccls && ldconfig      

RUN git clone --branch v1.12.0 --depth 1 https://github.com/google/flatbuffers.git && \
    cd flatbuffers && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release && \
    make && make install && ldconfig


RUN git clone --depth=1 https://github.com/google/googletest.git && \
    cd googletest && mkdir build && cd build && \
    cmake .. -DBUILD_SHARED_LIBS=ON -DINSTALL_GTEST=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr && \
    make -j8 && make install && ldconfig

RUN ln -s /usr/bin/clang-9 /usr/bin/clang && \
    ln -s /usr/bin/clang++-9 /usr/bin/clang++ && \
    ln -sf /usr/bin/ld /usr/bin/ld.gold && \
    pip3 install numpy pycryptodome ecdsa Pillow flatbuffers keras tensorflow-gpu tqdm

ENV SGX_SDK=${ARG_SGX_SDK}
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'
COPY --from=builder /linux-sgx/external/dnnl/sgx_dnnl/lib/libsgx_dnnl.a ${ARG_SGX_SDK}/lib64/
COPY --from=builder /linux-sgx/external/dnnl/sgx_dnnl/include/* ${ARG_SGX_SDK}/include/


#RUN adduser -q --disabled-password --gecos "" --no-create-home aref

WORKDIR /projects
RUN git clone --recursive https://^Cthub.com/pytorch/pytorch --branch v1.5.0 --single-branch && cd pytorch \
    &&  USE_NUMPY=0 BUILD_TEST=0 BUILD_CAFFE2_OPS=0 USE_SYSTEM_NCCL=0 USE_DISTRIBUTED=0 python3 setup.py install \
    && cd .. && rm -rf pytorch
COPY --from=builder /linux-sgx/SampleCode .

USER ${USERNAME}

CMD /bin/bash
