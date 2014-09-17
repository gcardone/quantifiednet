#ifndef qnflow_h_
#define qnflow_h_

#include <cstdint>
#include <iostream>
#include <sys/time.h>
#include "qnconnection.h"

class QNFlow {
public:
  QNFlow(const QNConnection& qnconnection, const struct timeval& start_time);
  const struct timeval& end_time() const;
  uint64_t sent_a() const;
  uint64_t sent_b() const;
  const struct timeval& start_time() const;
  void AddSentA(uint64_t size);
  void AddSentB(uint64_t size);
  void AddSent(in_addr_t addr, uint64_t size);
  const QNConnection& connection() const;
  friend std::ostream& operator<<(std::ostream& os, const QNFlow& o);
private:
  void UpdateEndTime(const struct timeval& end_time);
  void UpdateEndTime();
  QNConnection connection_;
  uint64_t sent_a_;
  uint64_t sent_b_;
  struct timeval start_time_;
  struct timeval end_time_;
};

#endif
