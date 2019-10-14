#pragma once
#include "Channel/IOneWaySender.hpp"

class SimpleOneWaySender
    : virtual public IlOneWaySender<SimpleOneWaySender> {
public:
  void sendDerivedimpl(const std::vector<uint8_t> &bytes,
                       const size_t len) const;
  explicit SimpleOneWaySender();
  ~SimpleOneWaySender() = default;
protected:
private:
};

