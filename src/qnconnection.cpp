#include <algorithm>
#include <cstring>
#include <exception>
#include <arpa/inet.h>
#include "qnconnection.h"
#include "util.h"


QNConnection::QNConnection(in_addr_t addr_a, uint16_t port_a, in_addr_t addr_b, uint16_t port_b) {
  if (addr_a < addr_b) {
    addr_a_ = addr_a;
    addr_b_ = addr_b;
    port_a_ = port_a;
    port_b_ = port_b;
  } else {
    addr_a_ = addr_b;
    addr_b_ = addr_a;
    port_a_ = port_b;
    port_b_ = port_a;
  }
}


QNConnection::QNConnection(const QNConnection& o) :
    port_a_(o.port_a_),
    port_b_(o.port_b_),
    addr_a_(o.addr_a_),
    addr_b_(o.addr_b_) {
}


in_addr_t QNConnection::addr_a() const {
  return addr_a_;
}


in_addr_t QNConnection::addr_b() const {
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
    addr_a_ = o.addr_a_;
    addr_b_ = o.addr_b_;
    port_a_ = o.port_a_;
    port_b_ = o.port_b_;
  }
  return *this;
}


bool QNConnection::operator==(const QNConnection& o) {
  return addr_a_ == o.addr_a_ &&
    addr_b_ == o.addr_b_ &&
    port_a_ == o.port_a_ &&
    port_b_ == o.port_b_;
}


bool QNConnection::operator!=(const QNConnection& o) {
  return !(*this == o);
}


bool QNConnection::operator<(const QNConnection& o) {
  if (addr_a_ < o.addr_a_) {
    return true;
  } else if (addr_a_ > o.addr_a_) {
    return false;
  }
  if (addr_b_ < o.addr_b_) {
    return true;
  } else if (addr_b_ > o.addr_b_) {
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
  std::string string_a = AddrToString(o.addr_a_);
  std::string string_b = AddrToString(o.addr_b_);
  os << '[' << string_a << "]:" << o.port_a_ << " <-> [" << string_b << "]:" << o.port_b_;
  return os;
}
