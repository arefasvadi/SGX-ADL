#pragma once
#include "Channel/BasicChannel.hpp"
#include <memory>
#include <vector>

template <typename Derived> class IChannelTwoWay {

public:
  void send(const std::vector<uint8_t> &bytes, const size_t len) const;
  std::vector<uint8_t> receive(const size_t len) const;

protected:
  const std::unique_ptr<BasicChannel<ChannelType::TwoWay>> channel_;

private:
  friend Derived;
  explicit IChannelTwoWay();
  ~IChannelTwoWay() = default;
};

template <typename Derived>
IChannelTwoWay<Derived>::IChannelTwoWay()
    : channel_(new BasicChannel<ChannelType::TwoWay>()) {}

template <typename Derived>
void IChannelTwoWay<Derived>::send(const std::vector<uint8_t> &bytes,
                                   const size_t len) const {
  static_cast<Derived &>(*this).sendDerivedimpl();
}

template <typename Derived>
std::vector<uint8_t> IChannelTwoWay<Derived>::receive(const size_t len) const {
  return static_cast<Derived &>(*this).receiveDerivedimpl();
}