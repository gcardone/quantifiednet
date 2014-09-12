#ifndef _qn_util
#define _qn_util

#include <string>
#include <netinet/in.h>

std::string AddrToString(in_addr_t addr);

in_addr_t StringToAddr(std::string addr);

/**
 * The memeq() function compares the first n bytes (each interpreted as
 * unsigned char) of the memory areas s1 and s2 for equality. It uses the
 * optimization described in Saunders, Richard T. "A Study in memcmp" to speed
 * up memory comparison for equality.
 * @param s1 First memory area
 * @param s2 Second memory area
 * @return 1 if the areas are equal, 0 if they are different.
 */
int memeq(const void* s1, const void* s2, size_t n);

#endif
