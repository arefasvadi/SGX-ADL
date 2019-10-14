#pragma once
#include "Channel/IOneWayReceiver.hpp"

class SimpleOneWayReceiver
    : virtual public IOneWayReceiver<SimpleOneWayReceiver> {
public:
  virtual ~SimpleOneWayReceiver() = default;
  std::vector<uint8_t> receiveDerivedimpl(const size_t len) const;
  explicit SimpleOneWayReceiver();

protected:
private:
};