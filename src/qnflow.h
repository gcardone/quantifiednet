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
