#include "Channel/SimpleTwoWayChannel.h"

SimpleTwoWayChannel::SimpleTwoWayChannel()
    : IChannelTwoWay<SimpleTwoWayChannel>() {}

void SimpleTwoWayChannel::sendDerivedimpl(const std::vector<uint8_t> &bytes,
                                          const size_t len) const {
  // we call the other sides receive
  const auto chan_id = this->channel_->getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
#ifdef USE_SGX
  res = ocall_receive_from_channel(chan_id, (unsigned char *)bytes.data(),
                                   bytes.size());
  CHECK_SGX_SUCCESS(
      res,
      "Sending to next end (which resides outside enclave) caused problem\n");
  abort();
#else
  res = ecall_receive_from_channel(global_eid, chan_id,
                                   (unsigned char *)bytes.data(), bytes.size());
  CHECK_SGX_SUCCESS(
      res,
      "Sending to next end (which resides inside enclave) caused problem\n");
  abort();
#endif
}

std::vector<uint8_t> SimpleTwoWayChannel::receiveDerivedimpl(
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