#include "rand/PRNGHelper.h"
#include "global-vars-trusted.h"
#include "rand/PRNG.h"
#include "common.h"
#include "util.h"
#include "hexString.h"

// std::unique_ptr<PRNGHelper>&
// derive_weights_init_seed(std::unique_ptr<PRNGHelper>& pub_init_helper) {
//     if (pub_init_helper->childs.count(0) > 0) {
//         return pub_init_helper->childs[0];
//     }
//     PRNG prng(pub_init_helper->init_seed);
//     std::unique_ptr<PRNGHelper> weghts_init_seed(
//         new PRNGHelper(pub_init_helper.get()));
//     for (int i=0;i<16;++i) {
//         auto rnd = prng.getRandomUint64();
//         std::memcpy(&(weghts_init_seed->init_seed[i]), &rnd,
//         sizeof(uint64_t));
//     }
//    pub_init_helper->childs[0] = std::move(weghts_init_seed);
//    return pub_init_helper->childs[0];
// }

// std::unique_ptr<PRNGHelper>&
// derive_epochs_init_seed(std::unique_ptr<PRNGHelper>& pub_init_helper, int n)
// {
//     if (pub_init_helper->childs.count(0) > 0) {
//         return pub_init_helper->childs[0];
//     }
// }

iteration_seed_t
get_iteration_seed(const std::array<uint64_t, 16>& root_seed,
                  const int                       iteration) {
  iteration_randomness_seed irs;
  std::memset(&irs,0,sizeof(irs));
  // LOG_DEBUG("root_seed calling to get iteration seed\n" COLORED_STR(YELLOW,"%s\n"),
  //   bytesToHexString((const uint8_t*)root_seed.data(),sizeof(uint64_t)*16).c_str())
  PRNG prng(root_seed);

  irs.iteration_number = iteration;
  for (int i=0;i<32;++i) {
    irs.it_seed.batch_layer_seed[i] = prng.getRandomUint64();
  }

  sgx_hmac_256bit_tag_t com_tag = {};

  auto ret = sgx_hmac_sha256_msg((unsigned char*)&irs,
                                 sizeof(iteration_randomness_seed_),
                                 enclave_cmac_key,
                                 SGX_CMAC_KEY_SIZE,
                                 com_tag,
                                 SGX_HMAC256_MAC_SIZE);
  CHECK_SGX_SUCCESS(ret, "sgx_hmac_sha256_msg")

  std::array<uint64_t,16> new_seed{};
  std::memcpy(new_seed.data(),com_tag,SGX_HMAC256_MAC_SIZE);

  prng.setSeed(new_seed);
  for (int i=0;i<32;++i) {
    irs.it_seed.batch_layer_seed[i] = prng.getRandomUint64();
  }

  // LOG_DEBUG("what call to get_iteration_seed generated at iteration %d\n"
  //   "1. <" COLORED_STR(RED,"%s") ">\n"
  //   "2. <" COLORED_STR(BRIGHT_GREEN,"%s") ">\n",
  //   iteration,
  //   bytesToHexString((uint8_t*)&irs.it_seed.batch_layer_seed[0],
  //     sizeof(uint64_t)*16).c_str(),
  //   bytesToHexString((uint8_t*)(&(irs.it_seed.batch_layer_seed[16])),
  //     sizeof(uint64_t)*16).c_str()
  //   )

  return irs.it_seed;
}