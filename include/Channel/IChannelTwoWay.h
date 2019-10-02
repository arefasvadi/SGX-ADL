#pragma once
#include "Channel/IChannel.h"
#include <vector>

class IChannelTwoWay : virtual public IChannelBase {

public:
  ~IChannelTwoWay() = default;
  virtual void send(const std::vector<uint8_t> &bytes,
                    const size_t len) const = 0;
  virtual std::vector<uint8_t> receive(const size_t len) const = 0;

protected:
  IChannelTwoWay();
  IChannelTwoWay(const IChannelIDType chan_id);

private:
};