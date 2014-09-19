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
