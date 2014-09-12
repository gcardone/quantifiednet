#include <cstdint>
#include <exception>
#include <iostream>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "util.h"


std::string AddrToString(const uint8_t* addr, int af) {
  char buff[INET6_ADDRSTRLEN];
  if (af == AF_INET) {
    if (inet_ntop(AF_INET, addr, buff, INET_ADDRSTRLEN) == NULL) {
        throw std::exception();
    }
  } else if (af == AF_INET6) {
    if (inet_ntop(AF_INET6, addr, buff, INET6_ADDRSTRLEN) == NULL) {
        throw std::exception();
    }
  }
  return std::string(buff);
}

int memeq(const void* s1, const void* s2, size_t n) {
  if (s1 == s2)
    return 1;

  /* convert pointers to largest native integers */
  const size_t *s1_int = static_cast<const size_t*>(s1);
  const size_t *s2_int = static_cast<const size_t*>(s2);

  size_t passes = n/sizeof(size_t);
  size_t mpasses = n & (sizeof(size_t) - 1);
  for (size_t i = 0; i < passes; i++) {
    if (*s1_int++ != *s2_int++) {
      return 0;
    }
  }

  const char *s1_chr = static_cast<const char*>(s1);
  const char *s2_chr = static_cast<const char*>(s2);
  for (size_t i = 0; i < mpasses; i++) {
    if (*s1_chr++ != *s2_chr++) {
      return 0;
    }
  }
  return 1;
}
