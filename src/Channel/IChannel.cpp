#pragma once
#include "Channel/IChannel.h"
#include "Channel/SimpleTwoWayChannel.h"

uint64_t IChannelBase::CURRENT_CHANNEL_ID = 0;

IChannelBase::IChannelBase() : channelID_(IChannelBase::CURRENT_CHANNEL_ID++) {}

IChannelBase::IChannelBase(const IChannelIDType chan_id) : channelID_(chan_id) {
  if (IChannelBase::CURRENT_CHANNEL_ID + 1 != channelID_) {
    throw std::runtime_error("channel id on this side is not sync");
  }
  IChannelBase::CURRENT_CHANNEL_ID = channelID_;
}

const IChannelBase::IChannelIDType IChannelBase::getCurrentChannelID() {
  return IChannelBase::CURRENT_CHANNEL_ID;
}

const IChannelBase::IChannelIDType IChannelBase::getChannelID() const {
  return this->channelID_;
}

const IChannelBase::ChannelType IChannelBase::getChannelType() const {
    return this->channelType_;
}

std::unique_ptr<IChannelBase> IChannelBase::GetNewChannel(ChannelType channel_type, bool last_end, IChannelIDType chan_id) {
    if (channel_type == ChannelType::OneWayReceiver) {
        std::runtime_error("One Way receiver not implemented!\n");
    }
    else if (channel_type == ChannelType::OneWaySender) {
        std::runtime_error("One Way sender not implemented!\n");
    }
    else if (channel_type == ChannelType::TwoWay) {
        SimpleTwoWayChannel* ptr = nullptr;
        if (last_end)
            ptr = new SimpleTwoWayChannel(chan_id);
        else 
            ptr = new SimpleTwoWayChannel();
        return std::unique_ptr<IChannelBase>(ptr);
    }
    std::runtime_error("not implemented!\n");
}

void IChannelBase::setChannelType(ChannelType channel_type) {
    this->channelType_ = channel_type;
}