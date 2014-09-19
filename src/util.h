#ifndef qnutil_h_
#define qnutil_h_

#include <string>

#include <netinet/in.h>
#include <sys/time.h>

std::string AddrToString(const in_addr_t addr);

in_addr_t StringToAddr(const std::string& addr);

std::string TimevalToString(const struct timeval& tv);

#endif
