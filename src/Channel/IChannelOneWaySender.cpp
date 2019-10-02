#include "Channel/IChannelOneWaySender.h"

IChannelOneWaySender::IChannelOneWaySender() : IChannelBase(){};
IChannelOneWaySender::IChannelOneWaySender(const IChannelIDType chan_id)
    : IChannelBase(chan_id){};
