# **SGX-ADL**

This project aims at a research project providing accountable deep learning.
The deep learning library used was a private fork of [darknet](https://github.com/pjreddie/darknet.git).


## CIFAR10 Experiments
### producing the dataset
either
1. run the serialize.py in `python/SGXADLPY/serialize.py` and make sure `process_cifar_10` is called. you may need to install keras, flatbuffers, and other python libraries. Usually `pip install foo` will suffice.
2. or download the serialized one from https://drive.google.com/file/d/1jCTyaRyoEvbHHvdFARTWyvxbiiWdy4i9/view?usp=drive_link

if option 2 is chosen then run the below command
```
cd PATH/SGX-ADL/test/config/cifar10

tar xvf PATH_TO_THE_TAR/cifar10_run_configs.tar
```
### compiling the sgxcode
```
# at the root directory of the project

# loads the darknet-patch into the current working directory
git submodule init
git submodule update

# you may need to have nvcc compiler and cuda headers
mkdir build && cd build
cmake -C ../cmake/CachePreloader.cmake ../
make -j8


# example run for verification in sgx via randomized matrix multiplication verification
./sgxdnnapp --loc ../test/config/cifar10/run_configs/locations/loc_cifar_vgg16_fc_nobn_g1_e1_b128_train_integrity_0.fb --tasktype train --verftype RMM

# verify via running entirely in sgx
./sgxdnnapp --loc ../test/config/cifar10/run_configs/locations/loc_cifar_vgg16_fc_nobn_g1_e1_b128_train_integrity_0.fb --tasktype train --verftype RF
```

## IMAGENET Experiments
Will update soon.

## Currently this is a clean up branch.
### **Planned For Migration**
- [x] Migrate to the new flatbuffers API, for marshaling and unmarshaling payloads from/to Enclave
- [x] Migrate to recommended usage of DNNL instead of custom patching of oneDNN
- [x] Compiles with the new CUDA compiler, and CPP std14 on Ubuntu

- [ ] Instead of `#ifdef` and conditional compilation, just build factories for different flavors, such as all_sgx, gpu_with_sgx_verification
  - [ ] Also, doing the same for the flavor of verification, such as full matrix multiplication, or Freivalds' matrix multiplication verification scheme
- [ ] Add full environement building instructions, in addition on how to run the experiments
  - [ ] Python experiments were sparse, probably they should be part of a different repo.
### **Nice to migrate too!**
- [ ] Integrate flatbuffers for all the crypto payloads
- [ ] Enhance argument parser
- [ ] Bundle everything into one docker container, and provide run commands for different experiments for SGX.