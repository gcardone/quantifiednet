#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>

#include "log.h"
#include "config.h"

int use_syslog = 0;

static void do_log(const char *prefix, const char *fmt, va_list args);

void info_log(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  do_log("[" COLOR_GREEN "INFO" COLOR_OFF "] ", fmt, args);
  va_end(args);
}

void debug_logf(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  do_log("[" COLOR_GREEN "DEBUG" COLOR_OFF "] ", fmt, args);
  va_end(args);
}

void err_log(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  do_log("[" COLOR_YELLOW "ERROR" COLOR_OFF "] ", fmt, args);
  va_end(args);
}

void critical_log(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  do_log("[" COLOR_RED "CRITICAL" COLOR_OFF "] ", fmt, args);
  va_end(args);

  _exit(EXIT_FAILURE);
}

static void do_log(const char *pre, const char *fmt, va_list args) {
  static char format[LINE_MAX_LEN];
  snprintf(format, LINE_MAX_LEN, "%s%s\n", pre, fmt);
  vfprintf(stderr, format, args);
}
