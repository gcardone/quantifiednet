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
