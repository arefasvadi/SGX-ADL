#include "app.h"
#include "sgx_urts.h"
#include "gtest/gtest.h"
#include <iostream>

namespace {

TEST(GeneralEnclave, CorrectInitAndDestroy) {
  //ASSERT_EQ(0, initialize_enclave());
  //ASSERT_EQ(SGX_SUCCESS, dest_enclave(global_eid));
}

TEST(GeneralEnclave, DestroyWithoutInit) {
  //ASSERT_NE(SGX_SUCCESS, dest_enclave(global_eid));
}

} // namespace