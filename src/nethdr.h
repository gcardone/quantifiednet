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

#ifndef nethdr_h_
#define nethdr_h_

#include <cstdint>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define SLL_ADDR_LEN   8

/**
 * This struct is needed when capturing from the "any" interface. See
 * http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html for more details
 */
struct linux_sll_hdr {
  uint16_t packet_type;
  uint16_t arphrd_type;
  uint16_t addr_len;
  uint8_t address[SLL_ADDR_LEN];
  uint16_t proto;
};


/**
 * libpcap DLT_EN10MB 802.3 ethernet header
 */
struct ether_hdr {
  uint8_t dst[ETHER_ADDR_LEN];
  uint8_t src[ETHER_ADDR_LEN];
  uint16_t ether_type; /* IP, ARP, RARP, etc. */
};

#define IP_VERSION(ip) (((ip)->vhl) >> 4)
#define IP_HL(ip)      (((ip)->vhl) & 0x0f)
#define IP_RF 0x8000       /* reserved fragment flag */
#define IP_DF 0x4000       /* dont fragment flag */
#define IP_MF 0x2000       /* more fragments flag */
#define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */

/**
 * IPv4 header.
 */
struct ip_hdr {
  uint8_t vhl;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  in_addr_t src;
  in_addr_t dest;
};


#define TCP_DOFF(th) ((th)->off_rsvd_ns >> 4)
#define TCP_NS(th) ((th)->off_rsvd_ns & 0x01)
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
 
/**
 * TCP header.
 */
struct tcp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint32_t seqno;
  uint32_t ackno;
  uint8_t off_rsvd_ns;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urg;
};

#endif
