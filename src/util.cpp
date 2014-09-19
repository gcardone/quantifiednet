#include <cstdint>
#include <exception>
#include <iostream>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#include "util.h"


std::string AddrToString(const in_addr_t addr) {
  char buff[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &addr, buff, INET_ADDRSTRLEN) == NULL) {
    throw std::exception();
  }
  return std::string(buff);
}


in_addr_t StringToAddr(const std::string& addr) {
  struct in_addr result;
  if (!inet_pton(AF_INET, addr.c_str(), &result)) {
    throw std::exception();
  }
  return result.s_addr;
}


std::string TimevalToString(const struct timeval& tv) {
  time_t time;
  struct tm* tm;
  char tmpbuf[64], buf[64];
  time = tv.tv_sec;
  tm = localtime(&time);
  strftime(tmpbuf, sizeof(tmpbuf), "%Y-%m-%d %H:%M:%S", tm);
  snprintf(buf, sizeof(buf), "%s.%03lu", tmpbuf, tv.tv_usec/1000);
  return std::string(buf);
}

