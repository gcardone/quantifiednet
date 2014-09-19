/*
 * Copyright (c) 2014, Giuseppe Cardone <ippatsuman@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL GIUSEPPE CARDONE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
