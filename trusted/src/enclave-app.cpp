#include "DNNTrainer.h"
#include "enclave_t.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
namespace sgt = ::sgx::trusted;

void printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
}

void ecall_enclave_init() {
  printf("enclave_init is called!\n");
  sgt::darknet::DNNTrainer trainer(
      "/home/aref/projects/SGX-DDL/test/config/cifar10/cifar_small.cfg", "",
      "");
  bool res = trainer.loadNetworkConfig();
  printf("%s:%d@%s =>  enclave_init finished loading network config!\n",
         __FILE__, __LINE__, __func__);
  if (!res) {
    printf("%s:%d@%s =>  trainer.loadNetworkConfig returned false\n", __FILE__,
           __LINE__, __func__);
  } else {
    printf("%s:%d@%s =>  trainer.loadNetworkConfig returned true\n", __FILE__,
           __LINE__, __func__);
  }
}
