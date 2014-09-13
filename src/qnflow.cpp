#include <sstream>
#include <string>
#include <arpa/inet.h>
#include "log.h"
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


uint64_t QNFlow::sent_a() const {
  return sent_a_;
}


uint64_t QNFlow::sent_b() const {
  return sent_b_;
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
    std::string straddr = AddrToString(addr);
    std::ostringstream oss;
    oss << connection_;
    std::string strconnection = oss.str();
    err_log("Unable to add %lu bytes to connection %s for address %s", size,
      strconnection.c_str(), straddr.c_str());
  }
}


const QNConnection& QNFlow::connection() {
    return connection_;
}

void QNFlow::UpdateEndTime(const struct timeval& end_time) {
    end_time_ = end_time;
}


void QNFlow::UpdateEndTime() {
    gettimeofday(&end_time_, NULL);
}

