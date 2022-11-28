# **SGX-ADL**

This project aims at a research project providing accountable deep learning.
The deep learning library used was a private fork of [darknet](https://github.com/pjreddie/darknet.git).


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