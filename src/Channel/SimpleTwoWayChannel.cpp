#include "Channel/SimpleTwoWayChannel.h"
#include "common.h"
#include "sgx_error.h"

#ifdef USE_SGX
#include "enclave_t.h"
#include "util.h"
#else
#include "enclave_u.h"
#include "sgx_eid.h"
extern sgx_enclave_id_t global_eid;
#endif

SimpleTwoWayChannel::SimpleTwoWayChannel() : IChannelTwoWay(){};

SimpleTwoWayChannel::SimpleTwoWayChannel(const IChannelIDType chan_id)
    : IChannelTwoWay(chan_id){};

void SimpleTwoWayChannel::setUpNextEnd() const {
  // instantiates an approporiate object on the other side
  const auto chan_id = getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
#ifdef USE_SGX
  res = ocall_setup_channel(chan_id,this->getChannelType());
  CHECK_SGX_SUCCESS(
      res,
      "Setting up next end (which resides outside enclave) caused problem\n");
  abort();
#else
  res = ecall_setup_channel(global_eid, chan_id,this->getChannelType());
  CHECK_SGX_SUCCESS(
      res,
      "Setting up next end (which resides inside enclave) caused problem\n");
  abort();
#endif
}

void SimpleTwoWayChannel::tearUpNextEnd() const {
  // deletes an approporiate object on the other side
  const auto chan_id = getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
#ifdef USE_SGX
  res = ocall_tearup_channel(chan_id);
  CHECK_SGX_SUCCESS(
      res,
      "Tearing up next end (which resides outside enclave) caused problem\n");
  abort();
#else
  res = ecall_tearup_channel(global_eid, chan_id);
  CHECK_SGX_SUCCESS(
      res,
      "Tearing up next end (which resides inside enclave) caused problem\n");
  abort();
#endif
}

void SimpleTwoWayChannel::send(const std::vector<uint8_t> &bytes,
                               const size_t len) const {
  // we call the other sides receive
  const auto chan_id = getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
#ifdef USE_SGX
  res = ocall_send_to_channel(chan_id, (unsigned char *)bytes.data(),
                              bytes.size());
  CHECK_SGX_SUCCESS(
      res,
      "Sending to next end (which resides outside enclave) caused problem\n");
  abort();
#else
  res = ecall_send_to_channel(global_eid, chan_id,
                              (unsigned char *)bytes.data(), bytes.size());
  CHECK_SGX_SUCCESS(
      res,
      "Sending to next end (which resides inside enclave) caused problem\n");
  abort();
#endif
}

std::vector<uint8_t> SimpleTwoWayChannel::receive(const size_t len) const {
  const auto chan_id = getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
  std::vector<uint8_t> bytes(len);
#ifdef USE_SGX
  res = ocall_receive_from_channel(chan_id, (unsigned char *)bytes.data(),
                                   bytes.size());
  CHECK_SGX_SUCCESS(res, "Receiving from next end (which resides outside "
                         "enclave) caused problem\n");
  abort();
#else
  res = ecall_receive_from_channel(global_eid, chan_id,
                                   (unsigned char *)bytes.data(), bytes.size());
  CHECK_SGX_SUCCESS(res, "Receiving from next end (which resides inside "
                         "enclave) caused problem\n");
  abort();

  return bytes;
#endif
}