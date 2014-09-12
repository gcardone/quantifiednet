#ifndef _qnconnection
#define _qnconnection

#include <cstdint>
#include <cstddef>
#include <iostream>

#include <netinet/in.h>

class QNConnection {
public:
  QNConnection(in_addr_t addr_a,uint16_t port_a, in_addr_t addr_b, uint16_t port_b);
  QNConnection(const QNConnection& o);
  in_addr_t addr_a() const;
  in_addr_t addr_b() const;
  uint16_t port_a() const;
  uint16_t port_b() const;
  QNConnection& operator=(const QNConnection& o);
  bool operator==(const QNConnection& o);
  bool operator!=(const QNConnection& o);
  bool operator<(const QNConnection& o);
  bool operator>(const QNConnection& o);
  bool operator<=(const QNConnection& o);
  bool operator>=(const QNConnection& o);
  friend std::ostream& operator<<(std::ostream& os, const QNConnection& o);
protected:
  uint16_t port_a_;
  uint16_t port_b_;
  in_addr_t addr_a_;
  in_addr_t addr_b_;
};

#endif
