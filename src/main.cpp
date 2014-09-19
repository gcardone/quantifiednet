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
  std::set<in_addr_t> local_ips;
  std::string database;
  std::string interface;
  sqlite3* pDB;
  int pcap_dl_type;
  sqlite3_stmt* pStmt;
  std::map<QNConnection, QNFlow> traffic;
  int verbose;
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = static_cast<struct arguments*>(state->input);
  switch (key) {
    case 'v':
      arguments->verbose = 1;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num > 2) {
        argp_usage(state);
      }
      if (state->arg_num == 0) {
        arguments->interface = arg;
      } else {
        arguments->database = arg;
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

static bool InitDbOrDie(struct arguments& arguments) {
  std::string file_uri;
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
  file_uri = "file:" + arguments.database;
  std::cout << "Using " << file_uri << " as Sqlite3 db" << std::endl;
  sqlite3_config(SQLITE_CONFIG_URI, 1);
  rc = sqlite3_open_v2(file_uri.c_str(), &pDB, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
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
  rc = sqlite3_prepare_v2(pDB, insert_query.c_str(), insert_query.length(), &(arguments.pStmt), NULL);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(arguments.pStmt);
    sqlite3_close(pDB);
    std::cout << "Error: " << sqlite3_errstr(rc) << std::endl;
    exit(EXIT_FAILURE);
  }
  arguments.pDB = pDB;
  arguments.database = file_uri;
  return true;
}

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


static void CheckIntfOrDie(const std::string& ifa, struct arguments& arg) {
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
  arg.pcap_dl_type = dl_type;
  pcap_close(pcap);
}


// evil global goes here: sorry, I need it in the signal handler.
static pcap_t *p;

static void SigHandler(int sig) {
  if (p != NULL) {
    pcap_breakloop(p);
  }
}


static void StoreFlowInDB(const arguments& args, const QNFlow& flow) {
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


static void ProcessPkt(unsigned char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct arguments* args;
  const struct ip_hdr* ip_hdr;
  const struct tcp_hdr* tcp_hdr;
  size_t datalink_size;
  size_t ip_size;
  struct timeval now;

  args = reinterpret_cast<struct arguments*>(user);
  
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
    // new connection
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
      StoreFlowInDB(*args, pflow->second);
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
      StoreFlowInDB(*args, it->second);
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
  if (args.database.empty()) {
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
