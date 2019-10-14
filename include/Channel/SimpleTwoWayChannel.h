#pragma once
#include "Channel/IChannelTwoWay.hpp"

class SimpleTwoWayChannel : virtual public IChannelTwoWay<SimpleTwoWayChannel> {

public:
  void sendDerivedimpl(const std::vector<uint8_t> &bytes,
                       const size_t len) const;
  std::vector<uint8_t> receiveDerivedimpl(const size_t len) const;

protected:
private:
  explicit SimpleTwoWayChannel();
  ~SimpleTwoWayChannel() = default;
};