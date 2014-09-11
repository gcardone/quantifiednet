#include <algorithm>
#include <cstring>
#include "qnconnection.h"
#include "util.h"


QNConnection::QNConnection(const uint8_t *addr_a, const uint8_t *addr_b,
  size_t addrlen, uint16_t port_a, uint16_t port_b) :
    addrlen_(addrlen),
    addr_a_(new uint8_t[addrlen]),
    addr_b_(new uint8_t[addrlen]) {
  addrlen_ = addrlen;
  if (std::memcmp(addr_a, addr_b, addrlen) < 0) {
    std::copy(addr_a, addr_a + addrlen, addr_a_);
    std::copy(addr_b, addr_b + addrlen, addr_b_);
    port_a_ = port_a;
    port_b_ = port_b;
  } else {
    std::copy(addr_a, addr_a + addrlen, addr_b_);
    std::copy(addr_b, addr_b + addrlen, addr_a_);
    port_b_ = port_a;
    port_a_ = port_b;
  }
}


QNConnection::QNConnection(const QNConnection& o) :
    addrlen_(o.addrlen_),
    port_a_(o.port_a_),
    port_b_(o.port_b_),
    addr_a_(new uint8_t[o.addrlen_]),
    addr_b_(new uint8_t[o.addrlen_]) {
  std::copy(o.addr_a_, o.addr_a_ + addrlen_, addr_a_);
  std::copy(o.addr_b_, o.addr_b_ + addrlen_, addr_b_);
  port_a_ = o.port_a_;
  port_b_ = o.port_b_;
}


size_t QNConnection::addrlen() const {
  return addrlen_;
}


const uint8_t* QNConnection::addr_a() const {
  return addr_a_;
}


const uint8_t* QNConnection::addr_b() const {
  return addr_b_;
}


uint16_t QNConnection::port_a() const {
  return port_a_;
}


uint16_t QNConnection::port_b() const {
  return port_b_;
}


QNConnection& QNConnection::operator=(const QNConnection& o) {
  if (this != &o) {
    if (addrlen_ != o.addrlen_) {
      delete[] addr_a_;
      delete[] addr_b_;
      addrlen_ = o.addrlen_;
      addr_a_ = new uint8_t[addrlen_];
      addr_b_ = new uint8_t[addrlen_];
    }
    std::copy(o.addr_a_, o.addr_b_ + addrlen_, addr_a_);
    std::copy(o.addr_b_, o.addr_b_ + addrlen_, addr_b_);
    port_a_ = o.port_a_;
    port_b_ = o.port_b_;
  }
  return *this;
}


bool QNConnection::operator==(const QNConnection& o) {
  return addrlen_ == o.addrlen_ &&
    port_a_ == o.port_a_ &&
    port_b_ == o.port_b_ &&
    memeq(addr_a_, o.addr_a_, sizeof(uint8_t) * addrlen_) &&
    memeq(addr_b_, o.addr_b_, sizeof(uint8_t) * addrlen_);
}


bool QNConnection::operator!=(const QNConnection& o) {
  return !(*this == o);
}


bool QNConnection::operator<(const QNConnection& o) {
  if (addrlen_ < o.addrlen_) {
    return true;
  } else if (addrlen_ > o.addrlen_) {
    return false;
  }
  int addrcmp = std::memcmp(addr_a_, o.addr_a_, sizeof(uint8_t) * addrlen_);
  if (addrcmp < 0) {
    return true;
  } else if (addrcmp > 0) {
    return false;
  }
  addrcmp = std::memcmp(addr_b_, o.addr_b_, sizeof(uint8_t) * addrlen_);
  if (addrcmp < 0) {
    return true;
  } else if (addrcmp > 0) {
    return false;
  }
  if (port_a_ < o.port_a_) {
    return true;
  } else if (port_a_ > o.port_a_) {
    return false;
  }
  if (port_b_ < o.port_b_) {
    return true;
  } else {
    return false;
  }
  return false;
}


bool QNConnection::operator>(const QNConnection& o) {
  return !((*this == o) || (*this < o));
}


bool QNConnection::operator<=(const QNConnection& o) {
  return (*this == o) || (*this < o);
}


bool QNConnection::operator>=(const QNConnection& o) {
  return (*this == o) || (*this > o);
}


std::ostream& operator<<(std::ostream& os, const QNConnection& o) {
  std::string string_a = AddrToString(o.addr_a_, o.addrlen_);
  std::string string_b = AddrToString(o.addr_b_, o.addrlen_);
  os << '[' << string_a << "]:" << o.port_a_ << " <-> [" << string_b << "]:" << o.port_b_;
  return os;
}


QNConnection::~QNConnection() {
  delete[] addr_a_;
  delete[] addr_b_;
}
