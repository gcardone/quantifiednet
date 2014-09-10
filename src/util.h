#ifndef _qn_util
#define _qn_util

#include <string>

std::string join_uint8(const uint8_t* data, const size_t len, const char sep = '.', const bool toHex = false);


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