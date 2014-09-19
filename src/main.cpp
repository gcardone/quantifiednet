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

#include <cstring>
#include <string>
#include <iostream>
#include <map>
#include <set>

#include <argp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/time.h>

#include "nethdr.h"
#include "qnconnection.h"
#include "qnflow.h"
#include "util.h"


const char *argp_program_version = "0.1";
const char *argp_program_bug_address = "<ippatsuman+quantifiednet@gmail.com>";
static char doc[] = "quantifiednet -- a minimal tracer of network connections";
static char args_doc[] = "INTERFACE DB";


static struct argp_option options[] = {
  {"INTERFACE",   0, 0,       OPTION_DOC, "Interface to listen on (e.g., eth0, any to listen on all available interfaces)",  1},
  {"DB",          0, 0,       OPTION_DOC, "Path to SQLite database",              1},
  {"verbose",   'v', 0,       0,          "Produce verbose output",               2},
  {0,             0, 0,       0,          0,                                      0}
};


struct arguments
{
  std::set<in_addr_t> local_ips; // set of local IPs
  std::string dbpath;            // URL of the destination SQLite db
  std::string interface;         // sniffing network interface
  sqlite3* pDB;                  // SQlite db
  int pcap_dl_type;              // data link type of the network interface
  sqlite3_stmt* pStmt;           // prepared stmt to insert connection data
  std::map<QNConnection, QNFlow> traffic; // tracked connections
  int verbose;                   // 1 for verbose mode
};


static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *args = static_cast<struct arguments*>(state->input);
  switch (key) {
    case 'v':
      args->verbose = 1;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num > 2) {
        argp_usage(state);
      }
      if (state->arg_num == 0) {
        args->interface = arg;
      } else {
        args->dbpath = arg;
      }
      break;
    case ARGP_KEY_END:
      if (state->arg_num < 2) {
        argp_usage(state);
      }
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}


static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL};


static void print_usage(void) {
  argp_help(&argp, stderr, ARGP_HELP_DOC, 0);
}


/**
 * Inits the target SQLite database. A prepared statement to quickly insert
 * traffic data in the database gets stored in the pStms field of arg. It
 * prints an error message and terminates the process if anything goes wrong
 * (e.g., the file is not accessible).
 * @param args Arguments structure
 */
static void InitDbOrDie(struct arguments& args) {
  std::string create_table =
    "create table if not exists tcp_connections (id integer primary key, " \
    "locip text not null, locport integer not null, remip text not null, " \
    "remport integer not null, sent integer not null, " \
    "rcvd integer not null, starttime text not null, " \
    "endtime text not null, durationmsec integer not null);";
  std::string insert_query = 
    "insert into tcp_connections(locip, locport, remip, remport, sent, " \
    "rcvd, starttime, endtime, durationmsec) values (?, ?, ?, ?, ?, ?, ?, ?, ?);";
  int rc;
  sqlite3 *pDB;
  sqlite3_stmt *pStmt;
  std::cout << "Using " << args.dbpath << " as Sqlite3 db" << std::endl;
  sqlite3_config(SQLITE_CONFIG_URI, 1);
  rc = sqlite3_open_v2(args.dbpath.c_str(), &pDB, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
  if (rc != SQLITE_OK) {
    sqlite3_close(pDB);
    std::cout << "Error: " << sqlite3_errstr(rc) << std::endl;
    exit(EXIT_FAILURE);
  }

  rc = sqlite3_prepare_v2(pDB, create_table.c_str(), create_table.length(), &pStmt, NULL);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    std::cout << "Error: " << sqlite3_errstr(rc) << std::endl;
    exit(EXIT_FAILURE);
  }

  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    std::cout << "Error: " << sqlite3_errstr(rc) << std::endl;
    exit(EXIT_FAILURE);
  }

  sqlite3_finalize(pStmt);
  rc = sqlite3_prepare_v2(pDB, insert_query.c_str(), insert_query.length(), &(args.pStmt), NULL);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(args.pStmt);
    sqlite3_close(pDB);
    std::cout << "Error: " << sqlite3_errstr(rc) << std::endl;
    exit(EXIT_FAILURE);
  }
  args.pDB = pDB;
}

/**
 * Retrieves all available AF_INET (IPv4) addresses and interfaces and stores
 * them in the function arguments. Kills the process in case getifaddrs(3)
 * fails.
 * @param addresses Where retrieved IPv4 addresses are stored.
 * @param interfaces Where retrieved interfaces are stored.
 */
static void GetLocalAddressesAndIntfOrDie(std::set<in_addr_t>& addresses, std::set<std::string>& interfaces) {
  struct ifaddrs *ifaddr, *ifa;
  int family;
  
  if (getifaddrs(&ifaddr) == -1) {
    std::cout << "Error: getifaddrs" << std::endl;
    exit(EXIT_FAILURE);
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }
    
    family = ifa->ifa_addr->sa_family;
    if (family != AF_INET) {
      continue;
    }
    in_addr_t s_addr = (reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr))->sin_addr.s_addr;
    addresses.insert(s_addr);
    interfaces.insert(ifa->ifa_name);
  }

  freeifaddrs(ifaddr);
}


/**
 * Checks that the interface stored in the arg parameter can be accessed by
 * libpcap (i.e., it exists and we have enough privileges to access it) and
 * that it is of a supported data link type (currently supported: Ethernet
 * and Linux "cooked" captured encapsulation. The interface data link type
 * is stored in the arg structure.
 * @param ifa Interface to check.
 * @param args Arguments structure.
 */
static void CheckIntfOrDie(const std::string& ifa, struct arguments& args) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;
  int dl_type;
  pcap = pcap_create(ifa.c_str(), errbuf);
  if (pcap == NULL) {
    std::cout << "Unable to open interface " << ifa << " for capture: " << errbuf << std::endl;
    exit(EXIT_FAILURE);
  }
  if (pcap_activate(pcap) != 0) {
    std::cout << "Unable to open interface " << ifa << " for capture: " << pcap_geterr(pcap) << std::endl;
    exit(EXIT_FAILURE);
  }
  dl_type = pcap_datalink(pcap);
  if (dl_type != DLT_LINUX_SLL && dl_type != DLT_EN10MB) {
    pcap_close(pcap);
    std::cout << "Interface " << ifa << " has datalink type " << \
        pcap_datalink_val_to_name(dl_type) << " (" << \
        pcap_datalink_val_to_description(dl_type) << "), which is not " \
        "currently supported";
    exit(EXIT_FAILURE);
  }
  args.pcap_dl_type = dl_type;
  pcap_close(pcap);
}


// evil global goes here: sorry, I need it in the signal handler.
static pcap_t *p;

/**
 * Signal handler that breaks packet capture loop
 * @param sig Received signal.
 */
static void SigHandler(int sig) {
  if (p != NULL) {
    pcap_breakloop(p);
  }
}


/**
 * Stores the data of the TCP flow in the SQLite database.
 * @param flow Flow to store.
 * @param args Program arguments.
 */
static void StoreFlowInDB(const QNFlow& flow, const arguments& args) {
  const QNConnection& conn = flow.connection();
  sqlite3_stmt* pStmt = args.pStmt;
  std::string srcip;
  std::string dstip;
  uint16_t srcport;
  uint16_t dstport;
  uint64_t sent;
  uint64_t rcvd;
  std::string starttime;
  std::string endtime;
  uint64_t durationmsec;
  int rc;

  // find which one of the TCP endpoints is a local interface
  if (args.local_ips.find(conn.addr_a()) != args.local_ips.end()) {
    srcip = AddrToString(conn.addr_a());
    srcport = ntohs(conn.port_a());
    dstip = AddrToString(conn.addr_b());
    dstport = ntohs(conn.port_b());
    sent = flow.sent_a();
    rcvd = flow.sent_b();
  } else {
    srcip = AddrToString(conn.addr_b());
    srcport = ntohs(conn.port_b());
    dstip = AddrToString(conn.addr_a());
    dstport = ntohs(conn.port_a());
    sent = flow.sent_b();
    rcvd = flow.sent_a();
  }
  starttime = TimevalToString(flow.start_time());
  endtime = TimevalToString(flow.end_time());
  sqlite3_bind_text(pStmt, 1, srcip.c_str(), srcip.length(), SQLITE_STATIC);
  sqlite3_bind_int(pStmt, 2, srcport);
  sqlite3_bind_text(pStmt, 3, dstip.c_str(), dstip.length(), SQLITE_STATIC);
  sqlite3_bind_int(pStmt, 4, dstport);
  sqlite3_bind_int64(pStmt, 5, sent);
  sqlite3_bind_int64(pStmt, 6, rcvd);
  sqlite3_bind_text(pStmt, 7, starttime.c_str(), starttime.length(), SQLITE_STATIC);
  sqlite3_bind_text(pStmt, 8, endtime.c_str(), endtime.length(), SQLITE_STATIC);
  durationmsec = (1000 * (flow.end_time().tv_sec -  flow.start_time().tv_sec) + flow.end_time().tv_usec / 1000) - flow.start_time().tv_usec / 1000;
  sqlite3_bind_int64(pStmt, 9, durationmsec);
  rc = sqlite3_step(pStmt);
  if (rc != SQLITE_DONE) {
    std::cout << "Error: " << sqlite3_errstr(rc) << std::endl;
  }
  sqlite3_reset(pStmt);
}

/**
 * Processes a single captured packet. See pcap_loop(3) for an in depth
 * description of function parameters.
 * @param user Pointer to a struct arguments.
 * @param h Pcap packet header.
 * @param bytes Captured packet, including data link header.
 */
static void ProcessPkt(unsigned char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct arguments* args;
  const struct ip_hdr* ip_hdr;
  const struct tcp_hdr* tcp_hdr;
  size_t datalink_size;
  size_t ip_size;
  struct timeval now;

  args = reinterpret_cast<struct arguments*>(user);
 
  // check whether the packet data link header is Linux SLL or Ethernet
  if (args->pcap_dl_type == DLT_LINUX_SLL) {
    ip_hdr = reinterpret_cast<const struct ip_hdr*>(bytes + sizeof(struct linux_sll_hdr));
    datalink_size = sizeof(struct linux_sll_hdr);
  } else {
    // args->pcap_dl_type == DLT_EN10MB
    datalink_size = sizeof(struct ether_hdr);
  }
  ip_hdr = reinterpret_cast<const struct ip_hdr*>(bytes + datalink_size);

  // discard non TCP packets
  if (ip_hdr->proto != IPPROTO_TCP)
      return;

  ip_size = IP_HL(ip_hdr)*sizeof(uint32_t);
  tcp_hdr = reinterpret_cast<const struct tcp_hdr*>(bytes + datalink_size + ip_size);
  QNConnection conn = QNConnection(ip_hdr->src, tcp_hdr->sport, ip_hdr->dest, tcp_hdr->dport);
  auto pflow = args->traffic.find(conn);
  if ((tcp_hdr->flags & TCP_SYN) && (tcp_hdr->flags & TCP_ACK)) {
    // new connection detected
    // A packet with SYN and ACK flags is sent as response to a SYN packet
    // Formally, the TCP three way handshake is not complete yet, so this might
    // going to be an incomplete connection. However, this is a simple and
    // robust enough approach.
    struct timeval now;
    gettimeofday(&now, NULL);
    QNFlow flow = QNFlow(conn, now);
    if (args->verbose) {
      std::cout << "New connection: " << conn << std::endl;
    }
    args->traffic.insert(std::make_pair(conn, flow));
  } else if (pflow != args->traffic.end()) {
    // tracked connection
    if ((tcp_hdr->flags & TCP_FIN) || (tcp_hdr->flags & TCP_RST)) {
      // closed connection
      // A TCP connection is closed when a packet with the RST or FIN flag is
      // sent/received. Actually, a FIN flag closes only one way of the
      // connection. Again, this is an oversimplification, still it works
      // decently.
      StoreFlowInDB(pflow->second, *args);
      if (args->verbose) {
        std::cout << "Closed connection: " << conn << std::endl;
      }
      args->traffic.erase(pflow);
    } else {
      // increase traffic size
      uint32_t len = ntohs(ip_hdr->len) - IP_HL(ip_hdr)*sizeof(uint32_t) - TCP_DOFF(tcp_hdr)*sizeof(uint32_t);
      pflow->second.AddSent(ip_hdr->src, len);
    }
  }

  // purge connections more than 120 seconds old without updates (default
  // timeout on Linux 2.2+ is 60 seconds)
  gettimeofday(&now, NULL);
  for (auto it = args->traffic.cbegin(); it != args->traffic.cend();) {
    if ((now.tv_sec - it->second.end_time().tv_sec) > 120) {
      StoreFlowInDB(it->second, *args);
      if (args->verbose) {
        std::cout << "Connection timed out: " << it->first;
      }
      args->traffic.erase(it++);
    } else {
      it++;
    }
  }
}


int main(int argc, char *argv[]) {
  struct arguments args;
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[] = "tcp";
  struct bpf_program filter;
  std::set<std::string> interfaces;

  args.verbose = 0;
  args.pDB = NULL;
  args.pStmt = NULL;
  argp_parse(&argp, argc, argv, 0, 0, &args);
  if (args.interface.empty()) {
    print_usage();
  }
  if (args.dbpath.empty()) {
    print_usage();
  }

  InitDbOrDie(args);

  std::cout << "Collecting local addresses" << std::endl;
  interfaces.insert("any");
  GetLocalAddressesAndIntfOrDie(args.local_ips, interfaces);
  if (interfaces.find(args.interface) == interfaces.end()) {
    std::cout << "Interface " << args.interface << " is not a valid " \
        "AF_INET interface";
    exit(EXIT_FAILURE);
  }

  std::cout << "Checkign capture interface " << args.interface << std::endl;
  CheckIntfOrDie(args.interface, args);

  std::cout << "Control-C to quit" << std::endl;
  if (signal(SIGINT, SigHandler) == SIG_ERR) {
    std::cout << "Error while installing signal handler" << std::endl;
    exit(EXIT_FAILURE);
  }
  if (signal(SIGHUP, SigHandler) == SIG_ERR) {
    std::cout << "Error while installing signal handler" << std::endl;
    exit(EXIT_FAILURE);
  }
  if (signal(SIGQUIT, SigHandler) == SIG_ERR) {
    std::cout << "Error while installing signal handler" << std::endl;
    exit(EXIT_FAILURE);
  }
  if (signal(SIGTERM, SigHandler) == SIG_ERR) {
    std::cout << "Error while installing signal handler" << std::endl;
    exit(EXIT_FAILURE);
  }

  p = pcap_create(args.interface.c_str(), errbuf);
  if (p == NULL) {
    std::cout << "Unable to open interface " << args.interface << " for " \
        "capture: " << errbuf << std::endl;
    exit(EXIT_FAILURE);
  }
  if (pcap_activate(p) != 0) {
    std::cout << "Unable to open interface " << args.interface << " for " \
        "capture: " << pcap_geterr(p) << std::endl;
    exit(EXIT_FAILURE);
  }
  args.pcap_dl_type = pcap_datalink(p);
  if (pcap_compile(p, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != 0) {
    std::cout << "Unable to compile filter expression: " << pcap_geterr(p) << std::endl;
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(p, &filter) != 0) {
    std::cout << "Unable to set filter: " << pcap_geterr(p) << std::endl;
    exit(EXIT_FAILURE);
  }
  pcap_loop(p, 0, ProcessPkt, reinterpret_cast<u_char*>(&args));
  pcap_freecode(&filter);
  pcap_close(p);
  sqlite3_finalize(args.pStmt);
  sqlite3_close(args.pDB);
  return 0;
}
