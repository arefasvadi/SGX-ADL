#pragma once
#include "common-structures.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>

//TODO: This class may need some refactoring and static polymorphism

#ifdef USE_SGX
#include "util.h"
#else
void main_logger(int level, const char *file, int line, const char *format,
                 ...);
#endif


typedef enum ChannelType{
    NOTInstantiated = 0,
    OneWayReceiver = 1,
    OneWaySender = 2,
    TwoWay = 3,
} ChannelType;

class IChannelBase {

public:
  using IChannelIDType = uint64_t;
  typedef enum ChannelType{
    NOTInstantiated = 0,
    OneWayReceiver = 1,
    OneWaySender = 2,
    TwoWay = 3,
} ChannelType;
public:
  virtual ~IChannelBase() = default;
  virtual void setUpNextEnd() const = 0;
  virtual void tearUpNextEnd() const = 0;
  static const IChannelIDType getCurrentChannelID();
  const IChannelIDType getChannelID() const;
  const ChannelType getChannelType() const;
  void setChannelType(ChannelType channel_type);
  static std::unique_ptr<IChannelBase> GetNewChannel(ChannelType channel_type, bool last_end,IChannelIDType chan_id);

protected:
  IChannelBase();
  IChannelBase(const IChannelIDType chan_id);

private:
  static IChannelIDType CURRENT_CHANNEL_ID;
  IChannelIDType channelID_;
  ChannelType channelType_;
};

// class IChannelBase {

// protected:
//   typedef ::ChannelType InnerChannelType;

// public:
//   virtual ~IChannelBase() = default;

//   // sends thisID_ to other side and gets thisID_ of other side and stores it
//   in
//   // thatID_
//   virtual uint64_t initSyncChannelWithOther(const uint64_t this_id) = 0;
//   virtual void sendTo(size_t record_id, size_t start, size_t len,
//                       const std::vector<uint8_t> &buff) const = 0;
//   virtual std::vector<uint8_t> recieveFrom(size_t record_id, size_t start,
//                                            size_t len) const = 0;

//   static std::unique_ptr<IChannelBase> getNewChannel(InnerChannelType
//   chan_type); const InnerChannelType &getChannelType() const { return
//   channelType_; };

// protected:
//   uint64_t thisID_;
//   uint64_t thatID_;

//   explicit IChannelBase(const InnerChannelType chan_type);
//   // Forces derive classes to be only instantiated through the base class;
//   struct _constructor_tag { explicit _constructor_tag() = default; };
//   static uint64_t currentID_;

// private:
//   InnerChannelType channelType_;
// };

// class OneWayChannelSender : public IChannelBase {

// public:
//   explicit OneWayChannelSender(const InnerChannelType
//   chan_type,_constructor_tag) : IChannelBase(chan_type){}; virtual uint64_t
//   initSyncChannelWithOther(const uint64_t this_id) override; virtual void
//   sendTo(size_t record_id, size_t start, size_t len,
//                       const std::vector<uint8_t> &buff) const override;
// private:
//   virtual std::vector<uint8_t> recieveFrom(size_t record_id, size_t start,
//                                            size_t len) const override final {
//     throw std::runtime_error("One Way Sender Channel Should Not Receive\n");
//   };
// };

// class OneWayChannelReceiver : public IChannelBase {

// public:
//   explicit OneWayChannelReceiver(const InnerChannelType
//   chan_type,_constructor_tag) : IChannelBase(chan_type){}; virtual uint64_t
//   initSyncChannelWithOther(const uint64_t this_id) override; virtual
//   std::vector<uint8_t> recieveFrom(size_t record_id, size_t start,
//                                            size_t len) const override;
// private:
//   virtual void sendTo(size_t record_id, size_t start, size_t len,
//                       const std::vector<uint8_t> &buff) const override final
//                       {
//     throw std::runtime_error("One Way Sender Channel Should Not Receive\n");
//   };
// };

// class TwoWayChannel : public IChannelBase {

// public:
//   explicit TwoWayChannel(const InnerChannelType chan_type,_constructor_tag) :
//   IChannelBase(chan_type){}; virtual uint64_t initSyncChannelWithOther(const
//   uint64_t this_id) override; virtual void sendTo(size_t record_id, size_t
//   start, size_t len,
//                       const std::vector<uint8_t> &buff) const override;
//   virtual std::vector<uint8_t> recieveFrom(size_t record_id, size_t start,
//                                            size_t len) const override;
// private:
// };
