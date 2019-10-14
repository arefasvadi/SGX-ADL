#pragma once
#include "Channel/IChannel.hpp"

template <ChannelType chan_type>
class BasicChannel : virtual public IChannelBase<BasicChannel, chan_type> {
public:
  void setUpNextEndDerivedimpl() const;
  void tearUpNextDerivedEndimpl() const;

  explicit BasicChannel();
  explicit BasicChannel(const IChannelBaseCommon::IChannelIDType chan_id);
};

template <ChannelType chan_type>
BasicChannel<chan_type>::BasicChannel()
    : IChannelBase<BasicChannel, chan_type>(){

      };

template <ChannelType chan_type>
BasicChannel<chan_type>::BasicChannel(
    const IChannelBaseCommon::IChannelIDType chan_id)
    : IChannelBase<BasicChannel, chan_type>(chan_id){

      };

template <ChannelType chan_type>
void BasicChannel<chan_type>::setUpNextEndDerivedimpl() const {
  // instantiates an approporiate object on the other side
  const auto chan_id = BasicChannel<chan_type>::getChannelID();
  sgx_status_t res = SGX_ERROR_UNEXPECTED;
#ifdef USE_SGX
  res = ocall_setup_channel(chan_id, this->getChannelType());
  CHECK_SGX_SUCCESS(
      res,
      "Setting up next end (which resides outside enclave) caused problem\n");
  abort();
#else
  res = ecall_setup_channel(global_eid, chan_id, this->getChannelType());
  CHECK_SGX_SUCCESS(
      res,
      "Setting up next end (which resides inside enclave) caused problem\n");
  abort();
#endif
};

template <ChannelType chan_type>
void BasicChannel<chan_type>::tearUpNextDerivedEndimpl() const {
  // deletes an approporiate object on the other side
  const auto chan_id = BasicChannel<chan_type>::getChannelID();
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
};