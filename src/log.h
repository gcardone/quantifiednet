#ifndef qnlog_h_
#define qnlog_h_

#define COLOR_GREEN	    "[1;32m"
#define COLOR_YELLOW    "[1;33m"
#define COLOR_RED	    "[1;31m"
#define COLOR_OFF	    "[0m"

void info_log(const char *fmt, ...);
void debug_log(const char *fmt, ...);
void err_log(const char *fmt, ...);
void critical_log(const char *fmt, ...);

#endif
