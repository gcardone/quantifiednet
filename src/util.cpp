#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "util.h"
#include <cstdio>


std::string JoinUint8(const uint8_t* data, const size_t len, const char sep, const bool toHex) {
  std::ostringstream oss;
  const uint8_t *p = data;
  if (toHex) {
    oss << std::hex << std::setfill ('0') << std::setw(2); 
  }
  if (len > 0) {
    oss << int(*p++);
  }
  while (p < data + len) {
    oss << sep;
    oss << int(*p++);
  }
  return oss.str();
}


std::string AddrToString(const uint8_t* addr, const size_t len) {
  char sep = len == 4 ? '.' : ':';
  bool toHex = len == 4 ? false : true;
  return JoinUint8(addr, len, sep, toHex);
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
