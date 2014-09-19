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

#ifndef qnconnection_h_
#define qnconnection_h_

#include <cstdint>
#include <cstddef>
#include <iostream>

#include <netinet/in.h>

/**
 * This class models a single TCP connection, uniquely identified by its
 * endpoints' addresses and ports. It supports ordering, thus it is safe to use
 * as map keys.
 */
class QNConnection {
public:
  /**
   * Constructs a new connection. addr_a and addr_b are compared for ordering
   * thus QConnection(A, ..., B, ...) and QConnection(B, ..., A, ...) build the
   * same object.
   */
  QNConnection(in_addr_t addr_a, uint16_t port_a, in_addr_t addr_b, uint16_t port_b);
  in_addr_t addr_a() const;
  in_addr_t addr_b() const;
  uint16_t port_a() const;
  uint16_t port_b() const;
  QNConnection& operator=(const QNConnection& o);
  friend bool operator==(const QNConnection& a, const QNConnection& b);
  friend bool operator!=(const QNConnection& a, const QNConnection& b);
  friend bool operator<(const QNConnection& a, const QNConnection& b);
  friend bool operator>(const QNConnection& a, const QNConnection& b);
  friend bool operator<=(const QNConnection& a, const QNConnection& b);
  friend bool operator>=(const QNConnection& a, const QNConnection& b);
  friend std::ostream& operator<<(std::ostream& os, const QNConnection& o);
protected:
  uint16_t port_a_;
  uint16_t port_b_;
  in_addr_t addr_a_;
  in_addr_t addr_b_;
};

#endif
