#include <cstdlib>
#include "util.h"

/**
 * The memeq() function compares the first n bytes (each interpreted as
 * unsigned char) of the memory areas s1 and s2 for equality. It uses the
 * optimization described in Saunders, Richard T. "A Study in memcmp" to speed
 * up memory comparison for equality.
 * @param s1 First memory area
 * @param s2 Second memory area
 * @return 0 if the areas are equal, 1 if they are different.
 */
int memeq(const void* s1, const void* s2, size_t n) {
    if (s1 == s2)
        return 0;

    /* convert pointers to largest native integers */
    const size_t *s1_int = static_cast<const size_t*>(s1);
    const size_t *s2_int = static_cast<const size_t*>(s2);

    size_t passes = n/sizeof(size_t);
    size_t mpasses = n & (sizeof(size_t) - 1);
    for (size_t i = 0; i < passes; i++) {
        if (*s1_int++ != *s2_int++) {
            return 1;
        }
    }

    const char *s1_chr = static_cast<const char*>(s1);
    const char *s2_chr = static_cast<const char*>(s2);
    for (size_t i = 0; i < mpasses; i++) {
        if (*s1_chr++ != *s2_chr++) {
            return 1;
        }
    }
    return 0;
}
