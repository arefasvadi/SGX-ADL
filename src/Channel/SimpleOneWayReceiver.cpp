#include "Channel/IOneWayReceiver.hpp"
#include "Channel/SimpleOneWayReceiver.h"

SimpleOneWayReceiver::SimpleOneWayReceiver()
    : IOneWayReceiver<SimpleOneWayReceiver>() {}

std::vector<uint8_t> SimpleOneWayReceiver::receiveDerivedimpl(
    const size_t len) const {
  const auto chan_id = this->channel_->getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t> bytes(len);
#ifdef USE_SGX
  res = ocall_send_to_channel(chan_id, (unsigned char *)bytes.data(),
                              bytes.size());
  CHECK_SGX_SUCCESS(res, "Receiving from next end (which resides outside "
                         "enclave) caused problem\n");
  abort();
#else
  res = ecall_send_to_channel(global_eid, chan_id,
                              (unsigned char *)bytes.data(), bytes.size());
  CHECK_SGX_SUCCESS(res, "Receiving from next end (which resides inside "
                         "enclave) caused problem\n");
  abort();
#endif
  return bytes;
}