#ifndef qnflow_h_
#define qnflow_h_

#include <cstdint>
#include <iostream>
#include <sys/time.h>
#include "qnconnection.h"


/**
 * Models a TCP data flow: the two endpoints addresses, data sent by each
 * endpoint, connection start time, time of the last data packet transfer.
 */
class QNFlow {
public:
  QNFlow(const QNConnection& qnconnection, const struct timeval& start_time);
  const struct timeval& end_time() const;
  /**
   * Data sent by addr_a (as specified by the underlying QNConnection)
   */
  uint64_t sent_a() const;
  /**
   * Data sent by addr_b (as specified by the underlying QNConnection)
   */
  uint64_t sent_b() const;
  const struct timeval& start_time() const;
  /**
   * Updates the number of bytes sent by addr_a. Automatically updates the
   * end_time.
   * @param size Number of bytes.
   */
  void AddSentA(uint64_t size);
  /**
   * Updates the number of bytes sent by addr_b. Automatically updates the
   * end_time.
   * @param size Number of sent bytes.
   */
  void AddSentB(uint64_t size);
  /**
   * Updates the number of bytes sent by addr. Automatically updates the
   * end_time.
   * @param addr Sender address. If addr is not addr_a nor addr_b, the
   * update is ignored.
   * @param size Number of sent bytes.
   */
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
