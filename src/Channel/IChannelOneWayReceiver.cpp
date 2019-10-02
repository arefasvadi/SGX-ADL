#include "Channel/IChannelOneWayReceiver.h"

IChannelOneWayReceiver::IChannelOneWayReceiver() : IChannelBase(){};
IChannelOneWayReceiver::IChannelOneWayReceiver(uint64_t chan_id)
    : IChannelBase(chan_id){};
