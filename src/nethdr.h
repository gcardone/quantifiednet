#ifndef nethdr_h_
#define nethdr_h_

#include <cstdint>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define SLL_ADDR_LEN   8

/* This struct is needed when capturing from the "any" interface. See
 * http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html for more details
 */
struct linux_sll_hdr {
  uint16_t packet_type;
  uint16_t arphrd_type;
  uint16_t addr_len;
  uint8_t address[SLL_ADDR_LEN];
  uint16_t proto;
};

/* Header when capturing from ethernet interface */
struct ether_hdr {
  uint8_t dst[ETHER_ADDR_LEN];
  uint8_t src[ETHER_ADDR_LEN];
  uint16_t ether_type; /* IP, ARP, RARP, etc. */
};

#define IP_VERSION(ip) ((ip)->vhl >> 4)
#define IP_HL(ip)      ((ip)->vhl & 0x0f)
#define IP_RF 0x8000       /* reserved fragment flag */
#define IP_DF 0x4000       /* dont fragment flag */
#define IP_MF 0x2000       /* more fragments flag */
#define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */

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
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
 

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
