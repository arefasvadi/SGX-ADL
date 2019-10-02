#include "app.h"
#include "sgx_urts.h"
#include "gtest/gtest.h"
#include <iostream>

namespace {

TEST(TEST_ENCLAVE, CORRECT_INIT_AND_DESTROY) {
  ASSERT_EQ(0, initialize_enclave());
  ASSERT_EQ(SGX_SUCCESS, dest_enclave(global_eid));
}

TEST(TEST_ENCLAVE, DESTROY_WITHOUT_INIT) {
  ASSERT_NE(SGX_SUCCESS, dest_enclave(global_eid));
}

} // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  return 0;
}
