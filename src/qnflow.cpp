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

#include <sstream>
#include <string>
#include <arpa/inet.h>
#include "qnflow.h"
#include "util.h"

QNFlow::QNFlow(const QNConnection& qnconnection, const struct timeval& start_time) :
    connection_(qnconnection),
    sent_a_(0),
    sent_b_(0),
    start_time_(start_time),
    end_time_(start_time)
{
}


const struct timeval& QNFlow::start_time() const {
  return start_time_;
}


uint64_t QNFlow::sent_a() const {
  return sent_a_;
}


uint64_t QNFlow::sent_b() const {
  return sent_b_;
}


const struct timeval& QNFlow::end_time() const {
  return end_time_;
}


void QNFlow::AddSentA(uint64_t size) {
  sent_a_ += size;
  UpdateEndTime();
}


void QNFlow::AddSentB(uint64_t size) {
  sent_b_ += size;
  UpdateEndTime();
}


void QNFlow::AddSent(in_addr_t addr, uint64_t size) {
  if (connection_.addr_a() == addr) {
    AddSentA(size);
  } else if (connection_.addr_b() ==  addr) {
    AddSentB(size);
  } else {
    std::cout << "Unable to add " << size << " bytes to connection " <<\
        connection_ << " for address " << AddrToString(addr) << std::endl;
  }
}


const QNConnection& QNFlow::connection() const {
    return connection_;
}

void QNFlow::UpdateEndTime(const struct timeval& end_time) {
    end_time_ = end_time;
}


void QNFlow::UpdateEndTime() {
    gettimeofday(&end_time_, NULL);
}


std::ostream& operator<<(std::ostream& os, const QNFlow& o) {
  os << "[" << AddrToString(o.connection_.addr_a()) << "]:" << ntohs(o.connection_.port_a());
  os << " (" << o.sent_a_ << " bytes) ";
  os << "<-> ";
  os << "[" << AddrToString(o.connection_.addr_b()) << "]:" << ntohs(o.connection_.port_b());
  os << " (" << o.sent_b_ << " bytes)";
  os << " start: " << TimevalToString(o.start_time_) << " - end: " << TimevalToString(o.end_time_);
  return os;
}
