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


bool operator==(const QNConnection& a, const QNConnection& b) {
  return a.addr_a_ == b.addr_a_ &&
    a.addr_b_ == b.addr_b_ &&
    a.port_a_ == b.port_a_ &&
    a.port_b_ == b.port_b_;
}


bool operator!=(const QNConnection& a, const QNConnection& b) {
  return !(a == b);
}


bool operator<(const QNConnection& a, const QNConnection& b) {
  if (a.addr_a_ < b.addr_a_) {
    return true;
  } else if (a.addr_a_ > b.addr_a_) {
    return false;
  }
  if (a.addr_b_ < b.addr_b_) {
    return true;
  } else if (a.addr_b_ > b.addr_b_) {
    return false;
  }
  if (a.port_a_ < b.port_a_) {
    return true;
  } else if (a.port_a_ > b.port_a_) {
    return false;
  }
  if (a.port_b_ < b.port_b_) {
    return true;
  } else {
    return false;
  }
  return false;
}


bool operator>(const QNConnection& a, const QNConnection& b) {
  return !((a == b) || (a < b));
}


bool operator<=(const QNConnection& a, const QNConnection& b) {
  return (a == b) || (a < b);
}


bool operator>=(const QNConnection& a, const QNConnection& b) {
  return (a == b) || (a > b);
}


std::ostream& operator<<(std::ostream& os, const QNConnection& o) {
  std::string string_a = AddrToString(o.addr_a_);
  std::string string_b = AddrToString(o.addr_b_);
  os << '[' << string_a << "]:" << ntohs(o.port_a_) << " <-> [" << string_b << "]:" << ntohs(o.port_b_);
  return os;
}
