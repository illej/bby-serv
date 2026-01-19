#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h> // TODO: roll own

#define ARRAY_LEN(ARR) (sizeof ((ARR)) / sizeof ((ARR)[0]))

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

// TODO: rename to 'timer'?
struct delayed_msg
{
    enum {
        RESET,
        TLS_SEND_PING,
        TLS_SEND_PONG,
        HTTP_SEND_KA,
    } type;
    int delay;
    bool pending;
    long started_at;
};

void enqueue (int type, int delay);
void timer_cancel (int type);

static bool
is_ascii (char val)
{
    return 31 < val && val < 127;
}

static char
to_ascii (uint8_t val)
{
    return is_ascii (val) ? val : '.';
}

static void
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
        asciip += sprintf (asciip, "%c ", to_ascii (buf[i]));
    }

    if (linep != line)
    {
        printf ("%02d:  %-24s\t%s\n", l, line, ascii);
    }

    printf ("\nBytes: %u\n", len);
    printf ("-----------------------------------------------\n");
}

static long
time_ms (void)
{
    struct timespec t;

    clock_gettime (CLOCK_BOOTTIME, &t);
    return (t.tv_sec * 1000) + (t.tv_nsec / 1.0e6); /* milliseconds */
}

struct buffer
{
    char *data;
    int len;

    char *_ptr;
    int _total;
    int _rem;
};

static inline void
buf_init (struct buffer *sb, char *buf, int buflen)
{
    memset (buf, 0, buflen);

    sb->data = buf;
    sb->len = 0;

    sb->_ptr = sb->data;
    sb->_total = buflen;
    sb->_rem = sb->_total;
}

static void buf_add_str (struct buffer *sb, char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
static void buf_add_str_chunked (struct buffer *sb, char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

static inline void
buf_add_str (struct buffer *sb, char *fmt, ...)
{
    va_list args;

    va_start (args, fmt);

    // TODO: rework so we can do an snprintf (NULL, 0, ..) to get the length
    int wr = vsnprintf (sb->_ptr, sb->_rem, fmt, args);
    sb->len += wr;
    sb->_ptr += wr;
    sb->_rem -= wr;

    va_end (args);
}

static inline void
buf_add_bytes (struct buffer *sb, char *bytes, size_t len)
{
    assert (len < sb->_rem);

    memcpy (sb->_ptr, bytes, len);

    sb->len += len;
    sb->_ptr += len;
    sb->_rem -= len;
}

static inline void
buf_add_str_chunked (struct buffer *sb, char *fmt, ...)
{
    va_list args;
    int wr;

    va_start (args, fmt);
    wr = vsnprintf (sb->_ptr, sb->_rem, fmt, args);
    va_end (args);

    // TODO: need until we can get rid of chunked-encoding
    int tmplen = wr + 32;
    char *tmp = malloc (tmplen);
    wr = snprintf (tmp, tmplen, "%x\r\n%s", wr, sb->_ptr);

    assert (sb->_rem > tmplen);
    memcpy (sb->_ptr, tmp, tmplen);

    sb->len += wr;
    sb->_ptr += wr;
    sb->_rem -= wr;

    free (tmp);
}

static inline u32
hash_str (char *str)
{
    u32 hash = 0;
    char c;

    while ((c = *str++))
    {
        hash += c;
        hash += hash << 10;
        hash ^= hash >> 6;
    }

    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    return hash;
}

#endif
