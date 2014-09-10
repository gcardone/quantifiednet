#ifndef _qnconnection
#define _qnconnection

#include <cstdint>
#include <cstdlib>
#include <iostream>

class QNConnection {
public:
    QNConnection(uint8_t *addr_1, uint8_t *addr_2, size_t addrlen, uint16_t port_1, uint16_t port_2);
    QNConnection(const QNConnection& o);
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
    uint8_t *addr_a;
    uint8_t *addr_b;
    uint16_t port_a;
    uint16_t port_b;
    size_t len;
};

#endif
