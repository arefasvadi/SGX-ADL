#pragma once
#include "Channel/BasicChannel.hpp"
#include <memory>
#include <vector>

template <typename Derived> class IOneWayReceiver {

public:
  std::vector<uint8_t> receive(const size_t len) const;

protected:
  const std::unique_ptr<BasicChannel<ChannelType::OneWayReceiver>> channel_;

private:
  friend Derived;
  ~IOneWayReceiver() = default;
  explicit IOneWayReceiver();

private:
};

template <typename Derived>
IOneWayReceiver<Derived>::IOneWayReceiver()
    : channel_(new BasicChannel<ChannelType::OneWayReceiver>()) {}

template <typename Derived>
std::vector<uint8_t> IOneWayReceiver<Derived>::receive(const size_t len) const {
  return static_cast<Derived &>(*this).receiveDerivedimpl();
}