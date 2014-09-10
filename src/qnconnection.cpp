#include <algorithm>
#include <cstring>
#include "qnconnection.h"
#include "util.h"

static void copyaddr(uint8_t *addr_a, uint8_t *addr_b, uint8_t *addr_1, uint8_t *addr_2, size_t addrlen) {
    if (memcmp(addr_1, addr_2, addrlen) < 0) {
        std::copy(addr_1, addr_1 + addrlen, addr_a);
        std::copy(addr_2, addr_2 + addrlen, addr_b);
    } else {
        std::copy(addr_1, addr_1 + addrlen, addr_b);
        std::copy(addr_2, addr_2 + addrlen, addr_a);
    }
}

static void copyport(uint16_t *port_a, uint16_t *port_b, uint16_t port_1, uint16_t port_2, uint8_t *addr_1, uint8_t *addr_2, size_t addrlen) {
    if (memcmp(addr_1, addr_2, addrlen) < 0) {
        *port_a = port_1;
        *port_b = port_2;
    } else {
        *port_b = port_1;
        *port_a = port_2;
    }
}


QNConnection::QNConnection(uint8_t *addr_1, uint8_t *addr_2, size_t addrlen, uint16_t port_1, uint16_t port_2) {
    addr_a = new uint8_t[addrlen];
    addr_b = new uint8_t[addrlen];
    len = addrlen;
    copyaddr(addr_a, addr_b, addr_1, addr_2, addrlen);
    copyport(&port_a, &port_b, port_1, port_2, addr_1, addr_2, addrlen);
}


QNConnection::QNConnection(const QNConnection& o) {
    if (len != o.len) {
        delete[] addr_a;
        delete[] addr_b;
        len = o.len;
        addr_a = new uint8_t[len];
        addr_b = new uint8_t[len];
    }
    std::copy(o.addr_a, o.addr_b + len, addr_a);
    std::copy(o.addr_b, o.addr_b + len, addr_b);
    port_a = o.port_a;
    port_b = o.port_b;
}


QNConnection& QNConnection::operator=(const QNConnection& o) {
    if (this != &o) {
        if (len != o.len) {
            delete[] addr_a;
            delete[] addr_b;
            len = o.len;
            addr_a = new uint8_t[len];
            addr_b = new uint8_t[len];
        }
        std::copy(o.addr_a, o.addr_b + len, addr_a);
        std::copy(o.addr_b, o.addr_b + len, addr_b);
        port_a = o.port_a;
        port_b = o.port_b;
    }
    return *this;
}


bool QNConnection::operator==(const QNConnection& o) {
    return len == o.len &&
           port_a == o.port_a &&
           port_b == o.port_b &&
           memeq(addr_a, o.addr_a, sizeof(uint8_t) * len) &&
           memeq(addr_b, o.addr_b, sizeof(uint8_t) * len);
}


bool QNConnection::operator!=(const QNConnection& o) {
    return !(*this == o);
}


bool QNConnection::operator<(const QNConnection& o) {
    if (len < o.len) {
        return true;
    } else if (len > o.len) {
        return false;
    }
    int addrcmp = memcmp(addr_a, o.addr_a, sizeof(uint8_t) * len);
    if (addrcmp < 0) {
        return true;
    } else if (addrcmp > 0) {
        return false;
    }
    addrcmp = memcmp(addr_b, o.addr_b, sizeof(uint8_t) * len);
    if (addrcmp < 0) {
        return true;
    } else if (addrcmp > 0) {
        return false;
    }
    if (port_a < o.port_a) {
        return true;
    } else if (port_a > o.port_a) {
        return false;
    }
    if (port_b < o.port_b) {
        return true;
    } else {
        return false;
    }
    return false;
}


bool QNConnection::operator>(const QNConnection& o) {
    return !((*this == o) || (*this < o));
}


bool QNConnection::operator<=(const QNConnection& o) {
    return (*this == o) || (*this < o);
}


bool QNConnection::operator>=(const QNConnection& o) {
    return (*this == o) || (*this > o);
}


QNConnection::~QNConnection() {
    delete[] addr_a;
    delete[] addr_b;
}
