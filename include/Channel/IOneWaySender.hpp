#pragma once
#include "Channel/BasicChannel.hpp"
#include <memory>
#include <vector>

template <typename Derived> class IlOneWaySender {
public:
  void send(const std::vector<uint8_t> &bytes, const size_t len) const;

protected:
  const std::unique_ptr<BasicChannel<ChannelType::OneWaySender>> channel_;

private:
  friend Derived;
  ~IlOneWaySender() = default;
  explicit IlOneWaySender();
};

template <typename Derived>
IlOneWaySender<Derived>::IlOneWaySender()
    : channel_(new BasicChannel<ChannelType::OneWaySender>()) {}

// template <template <typename> class Derived, typename DerivedChannel>
template <typename Derived>
void IlOneWaySender<Derived>::send(const std::vector<uint8_t> &bytes,
                                   const size_t len) const {
  static_cast<Derived &>(*this).sendDerivedimpl();
}