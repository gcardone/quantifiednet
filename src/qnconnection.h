#ifndef _qnconnection
#define _qnconnection

#include <cstdint>
#include <cstddef>
#include <iostream>

class QNConnection {
public:
    QNConnection(const uint8_t *addr_a, const uint8_t *addr_b, size_t addrlen, uint16_t port_a, uint16_t port_b);
    QNConnection(const QNConnection& o);
    size_t getAddrlen() const;
    const uint8_t* getAddrA() const;
    const uint8_t* getAddrB() const;
    uint16_t getPortA() const;
    uint16_t getPortB() const;
    QNConnection& operator=(const QNConnection& o);
    bool operator==(const QNConnection& o);
    bool operator!=(const QNConnection& o);
    bool operator<(const QNConnection& o);
    bool operator>(const QNConnection& o);
    bool operator<=(const QNConnection& o);
    bool operator>=(const QNConnection& o);
    virtual ~QNConnection();
    friend std::ostream& operator<<(std::ostream& os, const QNConnection& o);
protected:
    uint8_t *addr_a_;
    uint8_t *addr_b_;
    uint16_t port_a_;
    uint16_t port_b_;
    size_t addrlen_;
};

#endif
