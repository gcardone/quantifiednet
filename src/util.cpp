/*
 * Copyright (c) 2014, Giuseppe Cardone <ippatsuman@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL GIUSEPPE CARDONE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

