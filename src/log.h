#define COLOR_GREEN	    "[1;32m"
#define COLOR_YELLOW    "[1;33m"
#define COLOR_RED	    "[1;31m"
#define COLOR_OFF	    "[0m"

extern void info_log(const char *fmt, ...);
extern void debug_log(const char *fmt, ...);
extern void err_log(const char *fmt, ...);
extern void critical_log(const char *fmt, ...);
