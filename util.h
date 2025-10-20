#ifndef _UTIL_H_
#define _UTIL_H_

#include <time.h>

#define ARRAY_LEN(ARR) (sizeof ((ARR)) / sizeof ((ARR)[0]))

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

char
ascii_ (uint8_t val)
{
    if (val > 31 && val < 127)
        return val;
    return '.';
}

void
hex_dump (u8 *buf, size_t len)
{
    char line[1024];
    char ascii[512];
    int l = 0;
    char *linep = line;
    char *asciip = ascii;

    printf ("------------------- Hex Dump ------------------\n");

    for (int i = 0; i < len; i++)
    {
        if ((i % 8) == 0 && i != 0)
        {
            printf ("%02d:  %-24s\t%s\n", l++, line, ascii);
            linep = line;
            asciip = ascii;
        }

        linep += sprintf (linep, "%02x ", buf[i]);
        asciip += sprintf (asciip, "%c ", ascii_ (buf[i]));
    }

    if (linep != line)
    {
        printf ("%02d:  %-24s\t%s\n", l, line, ascii);
    }

    printf ("\nBytes: %u\n", len);
    printf ("-----------------------------------------------\n");
}

long
time_ms (void)
{
    struct timespec t;

    clock_gettime (CLOCK_BOOTTIME, &t);
    return (t.tv_sec * 1000) + (t.tv_nsec / 1.0e6); /* milliseconds */
}
#endif
