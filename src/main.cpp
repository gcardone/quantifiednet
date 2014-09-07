#include <string>
#include <argp.h>
#include <sqlite3.h>
#include "config.h"
#include "log.h"
#include "util.h"

const char *argp_program_version = QUANTIFIEDNET_FULL_VERSION;
const char *argp_program_bug_address = "<ippatsuman+quantifiednet@gmail.com>";

static char doc[] = "quantifiednet -- a minimal tracer of network connections";
static char args_doc[] = "INTERFACE DB";

static struct argp_option options[] = {
    {"INTERFACE",   0, 0,           OPTION_DOC, "Interface to listen on (e.g., eth0)",  1},
    {"DB",          0, 0,           OPTION_DOC, "Path to SQLite database",              1},
    {"verbose",   'v', 0,           0,          "Produce verbose output",               2},
    {        0,     0, 0,           0,          0,                                      0}
};


/* Used by main to communicate with parse_opt. */
struct arguments
{
    int verbose;
    std::string database;
    std::string interface;
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

static bool init_db(const std::string path) {
    std::string file_uri;
    std::string create_table =
        "create table if not exists tcp_connections (id integer primary key, " \
        "srcip text not null, srcport integer not null, dstip text not null, " \
        "dstport integer not null, sent integer not null, " \
        "rcvd integer not null, starttime integer not null, " \
        "endtime integer not null);";
    int rc;
    sqlite3 *pDB;
    sqlite3_stmt *pStmt;
    file_uri = "file:" + path;
    info_log("Using %s as Sqlite3 db", file_uri.c_str());
    sqlite3_config(SQLITE_CONFIG_URI, 1);
    rc = sqlite3_open_v2(file_uri.c_str(), &pDB, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(pDB);
        critical_log("%s", sqlite3_errstr(rc));
    }

    rc = sqlite3_prepare_v2(pDB, create_table.c_str(), create_table.length(), &pStmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(pStmt);
        sqlite3_close(pDB);
        critical_log("%s", sqlite3_errstr(rc));
    }

    rc = sqlite3_step(pStmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(pStmt);
        sqlite3_close(pDB);
        critical_log("%s", sqlite3_errstr(rc));
    }

    sqlite3_finalize(pStmt);
    sqlite3_close(pDB);
    return true;
}

int main(int argc, char *argv[]) {
    struct arguments arguments;
    arguments.verbose = 0;
    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    if (arguments.interface.empty()) {
        print_usage();
    }
    if (arguments.database.empty()) {
        print_usage();
    }
    init_db(arguments.database);
    return 0;
}
