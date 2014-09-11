#include <algorithm>
#include <cstring>
#include "qnconnection.h"
#include "util.h"


QNConnection::QNConnection(const uint8_t *addr_1, const uint8_t *addr_2, size_t addrlen, uint16_t port_1, uint16_t port_2) {
    mAddr_a = new uint8_t[addrlen];
    mAddr_b = new uint8_t[addrlen];
    mAddrlen = addrlen;
    if (std::memcmp(addr_1, addr_2, addrlen) < 0) {
        std::copy(addr_1, addr_1 + addrlen, mAddr_a);
        std::copy(addr_2, addr_2 + addrlen, mAddr_b);
        mPort_a = port_1;
        mPort_b = port_2;
    } else {
        std::copy(addr_1, addr_1 + addrlen, mAddr_b);
        std::copy(addr_2, addr_2 + addrlen, mAddr_a);
        mPort_b = port_1;
        mPort_a = port_2;
    }
}


QNConnection::QNConnection(const QNConnection& o) {
    if (mAddrlen != o.mAddrlen) {
        delete[] mAddr_a;
        delete[] mAddr_b;
        mAddrlen = o.mAddrlen;
        mAddr_a = new uint8_t[mAddrlen];
        mAddr_b = new uint8_t[mAddrlen];
    }
    std::copy(o.mAddr_a, o.mAddr_b + mAddrlen, mAddr_a);
    std::copy(o.mAddr_b, o.mAddr_b + mAddrlen, mAddr_b);
    mPort_a = o.mPort_a;
    mPort_b = o.mPort_b;
}


QNConnection& QNConnection::operator=(const QNConnection& o) {
    if (this != &o) {
        if (mAddrlen != o.mAddrlen) {
            delete[] mAddr_a;
            delete[] mAddr_b;
            mAddrlen = o.mAddrlen;
            mAddr_a = new uint8_t[mAddrlen];
            mAddr_b = new uint8_t[mAddrlen];
        }
        std::copy(o.mAddr_a, o.mAddr_b + mAddrlen, mAddr_a);
        std::copy(o.mAddr_b, o.mAddr_b + mAddrlen, mAddr_b);
        mPort_a = o.mPort_a;
        mPort_b = o.mPort_b;
    }
    return *this;
}


bool QNConnection::operator==(const QNConnection& o) {
    return mAddrlen == o.mAddrlen &&
           mPort_a == o.mPort_a &&
           mPort_b == o.mPort_b &&
           memeq(mAddr_a, o.mAddr_a, sizeof(uint8_t) * mAddrlen) &&
           memeq(mAddr_b, o.mAddr_b, sizeof(uint8_t) * mAddrlen);
}


bool QNConnection::operator!=(const QNConnection& o) {
    return !(*this == o);
}


bool QNConnection::operator<(const QNConnection& o) {
    if (mAddrlen < o.mAddrlen) {
        return true;
    } else if (mAddrlen > o.mAddrlen) {
        return false;
    }
    int addrcmp = std::memcmp(mAddr_a, o.mAddr_a, sizeof(uint8_t) * mAddrlen);
    if (addrcmp < 0) {
        return true;
    } else if (addrcmp > 0) {
        return false;
    }
    addrcmp = std::memcmp(mAddr_b, o.mAddr_b, sizeof(uint8_t) * mAddrlen);
    if (addrcmp < 0) {
        return true;
    } else if (addrcmp > 0) {
        return false;
    }
    if (mPort_a < o.mPort_a) {
        return true;
    } else if (mPort_a > o.mPort_a) {
        return false;
    }
    if (mPort_b < o.mPort_b) {
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


std::ostream& operator<<(std::ostream& os, const QNConnection& o) {
    char sep = o.mAddrlen == 4 ? '.' : ':';
    bool toHex = o.mAddrlen == 4 ? false : true;
    std::string string_a = join_uint8(o.mAddr_a, o.mAddrlen, sep, toHex);
    std::string string_b = join_uint8(o.mAddr_b, o.mAddrlen, sep, toHex);
    os << '[' << string_a << "]:" << o.mPort_a << " <-> [" << string_b << "]:" << o.mPort_b;
    return os;
}


QNConnection::~QNConnection() {
    delete[] mAddr_a;
    delete[] mAddr_b;
}
