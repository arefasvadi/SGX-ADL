#include "Channel/IChannelTwoWay.h"

IChannelTwoWay::IChannelTwoWay() : IChannelBase(){};
IChannelTwoWay::IChannelTwoWay(const IChannelIDType chan_id)
    : IChannelBase(chan_id){};
