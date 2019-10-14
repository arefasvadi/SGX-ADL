#pragma once
#include "common-structures.h"
#include "common.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <unordered_map>

// TODO: This class may need some refactoring and static polymorphism

#ifdef USE_SGX
#include "enclave_t.h"
#include "util.h"
#else
#include "enclave_u.h"
// #include "sgx_eid.h"
extern sgx_enclave_id_t global_eid;
void main_logger(int level, const char *file, int line, const char *format,
                 ...);
#endif

enum ChannelType { OneWaySender = 0, OneWayReceiver = 1, TwoWay = 2 };

struct IChannelBaseCommon {
  using IChannelIDType = uint64_t;
  static IChannelIDType CURRENT_CHANNEL_ID;
};

template <template <ChannelType> class Derived, ChannelType chan_type>
class IChannelBase : virtual public IChannelBaseCommon {

public:
  void setUpNextEnd() const;
  void tearUpNextEnd() const;
  static const IChannelIDType getCurrentChannelID();
  const IChannelIDType getChannelID() const;
  static const ChannelType getChannelType();
  static void
  AddNewChannelToRegistery(std::unique_ptr<Derived<chan_type>> channel_ptr);
  static std::unique_ptr<Derived<chan_type>>
  RemoveChannelFromRegistery(IChannelIDType chan_id);
  DISALLOW_COPY_AND_ASSIGN(IChannelBase);

protected:
private:
  // https://www.fluentcpp.com/2017/05/12/curiously-recurring-template-pattern/
  friend Derived<chan_type>;
  explicit IChannelBase();
  explicit IChannelBase(const IChannelIDType chan_id);
  ~IChannelBase() = default;

  const IChannelIDType channelID_;
  static constexpr ChannelType channelType_ = chan_type;
  static std::unordered_map<IChannelIDType, std::unique_ptr<Derived<chan_type>>>
      ChannelRegistery_;
};

template <template <ChannelType> class Derived, ChannelType chan_type>
std::unordered_map<IChannelBaseCommon::IChannelIDType,
                   std::unique_ptr<Derived<chan_type>>>
    IChannelBase<Derived, chan_type>::ChannelRegistery_ = {};

template <template <ChannelType> class Derived, ChannelType chan_type>
IChannelBase<Derived, chan_type>::IChannelBase()
    : channelID_(IChannelBase::CURRENT_CHANNEL_ID++) {}

template <template <ChannelType> class Derived, ChannelType chan_type>
IChannelBase<Derived, chan_type>::IChannelBase(const IChannelIDType chan_id)
    : channelID_(chan_id) {
  if (IChannelBase::CURRENT_CHANNEL_ID + 1 != channelID_) {
    throw std::runtime_error("channel id on this side is not sync");
  }
  IChannelBase::CURRENT_CHANNEL_ID = channelID_;
}

template <template <ChannelType> class Derived, ChannelType chan_type>
void IChannelBase<Derived, chan_type>::setUpNextEnd() const {
  static_cast<Derived<chan_type> &>(*this).setUpNextEndDerivedimpl();
}

template <template <ChannelType> class Derived, ChannelType chan_type>
void IChannelBase<Derived, chan_type>::tearUpNextEnd() const {
  static_cast<Derived<chan_type> &>(*this).tearUpNextDerivedEndimpl();
}

template <template <ChannelType> class Derived, ChannelType chan_type>
const IChannelBaseCommon::IChannelIDType
IChannelBase<Derived, chan_type>::getCurrentChannelID() {
  return IChannelBase::CURRENT_CHANNEL_ID;
}

template <template <ChannelType> class Derived, ChannelType chan_type>
const IChannelBaseCommon::IChannelIDType
IChannelBase<Derived, chan_type>::getChannelID() const {
  return this->channelID_;
}

template <template <ChannelType> class Derived, ChannelType chan_type>
const ChannelType IChannelBase<Derived, chan_type>::getChannelType() {
  return IChannelBase<Derived, chan_type>::channelType_;
}

template <template <ChannelType> class Derived, ChannelType chan_type>
void IChannelBase<Derived, chan_type>::AddNewChannelToRegistery(
    std::unique_ptr<Derived<chan_type>> channel_ptr) {
  IChannelBase<Derived,
               chan_type>::
               ChannelRegistery_[channel_ptr->getChannelID()] =
      std::move(channel_ptr);
}

template <template <ChannelType> class Derived, ChannelType chan_type>
std::unique_ptr<Derived<chan_type>>
RemoveChannelFromRegistery(IChannelBaseCommon::IChannelIDType chan_id) {
  if (IChannelBase<Derived, chan_type>::ChannelRegistery_.count(chan_id) < 1) {
    throw std::runtime_error("provided chan_id not in the registery!");
  }
  return std::unique_ptr<Derived<chan_type>>(
      IChannelBase<Derived, chan_type>::ChannelRegistery_[chan_id]);
}