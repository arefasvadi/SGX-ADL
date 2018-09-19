#include "enclave_t.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
#include "DNNTrainer.h"
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
namespace sgt = ::sgx::trusted;
sgt::darknet::DNNTrainer trainer("~/projects/SGX-DDL/test/config/cifar10/cifar_small.cfg","","");

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
}
