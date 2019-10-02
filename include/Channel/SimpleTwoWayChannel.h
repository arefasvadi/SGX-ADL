#pragma once
#include "Channel/IChannelTwoWay.h"


class SimpleTwoWayChannel : virtual public IChannelTwoWay {

public:
  SimpleTwoWayChannel();
  SimpleTwoWayChannel(const IChannelIDType chan_id);
  virtual ~SimpleTwoWayChannel() = default;
  virtual void setUpNextEnd() const override;
  virtual void tearUpNextEnd() const override;
  virtual void send(const std::vector<uint8_t> &bytes,
                    const size_t len) const override;
  virtual std::vector<uint8_t> receive(const size_t len) const override;
};