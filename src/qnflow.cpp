#include <sstream>
#include <string>
#include "log.h"
#include "qnflow.h"
#include "util.h"

QNFlow::QNFlow(const QNConnection& qnconnection, const struct timeval start_time) :
    connection(qnconnection),
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
}


void QNFlow::AddSentB(uint64_t size) {
  sent_b_ += size;
}


void QNFlow::AddSent(const uint8_t* addr, uint64_t size) {
  if (memeq(connection.addr_a(), addr, connection.addrlen())) {
    AddSentA(size);
  } else if (memeq(connection.addr_b(), addr, connection.addrlen())) {
    AddSentB(size);
  } else {
    std::string straddr = AddrToString(addr, connection.addrlen());
    std::ostringstream oss;
    oss << connection;
    std::string strconnection = oss.str();
    err_log("Unable to add %lu bytes to connection %s for address %s", size,
      strconnection.c_str(), straddr.c_str());
  }
}
