#pragma once
#include "Channel/IChannel.h"
#include <vector>

class IChannelOneWaySender : virtual public IChannelBase {

public:
  ~IChannelOneWaySender() = default;
  virtual void send(const std::vector<uint8_t> &bytes,
                    const size_t len) const = 0;

protected:
  IChannelOneWaySender();
  IChannelOneWaySender(const IChannelIDType chan_id);

private:
};