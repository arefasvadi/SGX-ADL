#pragma once
#include "Channel/IChannel.h"
#include <vector>

class IChannelOneWayReceiver : virtual public IChannelBase {

public:
  ~IChannelOneWayReceiver() = default;
  virtual std::vector<uint8_t> receive(const size_t len) const = 0;

protected:
  IChannelOneWayReceiver();
  IChannelOneWayReceiver(uint64_t chan_id);

private:
};