#ifndef _qnconnection
#define _qnconnection

#include <cstdint>
#include <cstddef>
#include <iostream>

class QNConnection {
public:
    QNConnection(const uint8_t *addr_1, const uint8_t *addr_2, size_t addrlen, uint16_t port_1, uint16_t port_2);
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
    uint8_t *mAddr_a;
    uint8_t *mAddr_b;
    uint16_t mPort_a;
    uint16_t mPort_b;
    size_t mAddrlen;
};

#endif
