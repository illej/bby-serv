#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <ctype.h>

#include "app.h"
#include "util.h"
#include "web.h"
#include "event.h"

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static unsigned int timestamp = 0;

static void
http_dump (char *buf, int len)
{
    char line[512] = {};
    char *p = line;

    printf ("----- HTTP -----\n");
    printf ("%d bytes:\n", len);
    for (int i = 0; i < len; i++)
    {
        if ((i % 80) == 0 && i != 0)
        {
            printf ("%s\n", line);
            p = line;
        }

        p += sprintf (p, "%c", to_ascii (buf[i]));
    }

    if (p != line)
    {
        printf ("%s\n", line);
    }
    printf ("----------------\n");
}

static struct buffer
build_response (char *data, size_t datalen, char *mime, char *buf, size_t buflen)
{
    struct buffer sb = {};

    buf_init (&sb, buf, buflen);

    buf_add_str (&sb, "HTTP/1.1 200 OK\r\n");
    buf_add_str (&sb, "Content-Type: %s\r\n", mime);
    buf_add_str (&sb, "Content-Length: %ld\r\n", datalen);
    buf_add_str (&sb, "\r\n");
    buf_add_str (&sb, "%s\r\n", data);
    buf_add_str (&sb, "\r\n");

    return sb;
}

static char *
read_file (char *file, long *len)
{
    FILE *fp;
    int wr = 0;
    long fsize = 0;
    char *data = NULL;

    fp = fopen (file, "r");
    if (fp)
    {
        fseek (fp, 0, SEEK_END);
        fsize = ftell (fp);
        fseek (fp, 0, SEEK_SET);

        data = malloc (fsize + 1);
        fread (data, fsize, 1, fp);
        data[fsize] = 0;

        *len = fsize;

        fclose (fp);
    }
    else
    {
        printf ("Failed to open file '%s'\n", file);
    }

    return data;
}

static long long
read_file_large (char *file, long long start, long long *total_len, char *buf, long long buflen)
{
    int fd;
    off_t fsize;
    long long rd = -1;

    fd = open (file, O_RDONLY);
    if (fd > 0)
    {
        fsize = lseek (fd, 0, SEEK_END);
        if (fsize < 0)
        {
            perror ("lseek");
        }

        lseek (fd, start, SEEK_SET);

        rd = read (fd, buf, buflen);
        if (rd < 0)
        {
            perror ("read");
        }

        close (fd);
    }

    assert (rd > 0);

    *total_len = fsize;
    return rd;
}

void
http_send (int sk, char *buf, size_t len, char *type)
{
    int wr = 0;

    do {
        wr = write (sk, buf + wr, len - wr);
    } while (wr > 0 && wr < len);

    if (wr == len)
    {
        printf ("http: SEND [%s] -> client(%d): OK %d bytes\n", type, sk, wr);
    }
    else
    {
        printf ("http: SEND [%s] -> client(%d): Failed %d errno:%d '%s'\n", type, sk, wr, errno, strerror (errno));
    }

    if (strcmp (type, "EVT") == 0)
    {
        http_dump (buf, len);
    }
}

void
http_event_send (struct web_server *web, char *type, char *data)
{
    struct sigaction newact, oldact;
    struct buffer sb = {};
    char buf[32 * 1024];

    buf_init (&sb, buf, sizeof (buf));
    if (type)
    {
        buf_add_str (&sb, "event: %s\ndata: %s\n\n", type, data);
    }
    else
    {
        buf_add_str (&sb, "data: %s\n\n", data);
    }

    newact.sa_handler = SIG_IGN;
    sigemptyset (&newact.sa_mask);
    newact.sa_flags = 0;
    sigaction (SIGPIPE, &newact, &oldact);

    for (int i = 0; i < web->client_count; i++)
    {
        if (web->streaming & (1 << i))
        {
            http_send (web->clients[i].fd, sb.data, sb.len, "EVT");
        }
    }

    sigaction (SIGPIPE, &oldact, NULL);
}

struct track
{
    char *name;
    unsigned int id;
    bool active; // TODO: could be an enum for playing/paused/none?
};

static struct track track_list[] = {
    { .name = "sonic-1.mp4", .id = 1111 },
    { .name = "sonic-2.mp4", .id = 2222 },
    { .name = "sonic-3.mp4", .id = 3333 },
    { .name = "frozen-1.mp4", .id = 4444, .active = true },
    { .name = "frozen-2.mp4", .id = 5555 },
};

void
http_event_send_start (int csk)
{
    struct buffer h;
    char httpbuf[256];

    buf_init (&h, httpbuf, sizeof (httpbuf));
    buf_add_str (&h, "HTTP/1.1 200 OK\r\n");
    buf_add_str (&h, "Connection: keep-alive\r\n");
    buf_add_str (&h, "Content-Type: text/event-stream\r\n");
    buf_add_str (&h, "Cache-Control: no-cache\r\n");
    buf_add_str (&h, "\r\n");

    struct sigaction newact, oldact;
    newact.sa_handler = SIG_IGN;
    sigemptyset (&newact.sa_mask);
    newact.sa_flags = 0;
    sigaction (SIGPIPE, &newact, &oldact);

    http_send (csk, h.data, h.len, "EVT");

    sigaction (SIGPIPE, &oldact, NULL);
}


static void
web_client_add (struct web_server *web, int sk)
{
    int printed = 0;

    if (web->client_count + 1 < WEB_CLIENT_MAX)
    {
        for (int i = 0; i < WEB_CLIENT_MAX; i++)
        {
            // printf ("http: finding free client slot [%d].fd=%d\n", i, web->clients[i].fd);
            if (web->clients[i].fd == -1)
            {
                web->clients[i].fd = sk;
                web->clients[i].events = POLLIN;
                web->client_count++;

                printf ("http: added client fd[%d]=%d\n", i, sk);
                break;
            }
        }
    }
    else
    {
        printf ("http: too many web clients\n");
    }

#if 0
    printf ("Web Clients (count=%d)\n", web->client_count);
    for (int i = 0; i < WEB_CLIENT_MAX; i++)
    {
        if (printed == web->client_count)
            break;

        printf (" [%d] .fd=%d .streaming=%d\n", i, web->clients[i].fd, !!(web->streaming & (1 << i)));

        if (web->clients[i].fd > 0)
            printed++;
    }
#endif
}


void
http_accept (struct web_server *web)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof (client_addr);

    int csk = accept (web->listen_sk, (struct sockaddr *) &client_addr, &addr_len);
    if (csk > -1)
    {
        web_client_add (web, csk);
    }
    else
    {
        printf ("accept() failed: errno=%d '%s'\n", errno, strerror (errno));
    }
}

static void
web_client_del (struct web_server *web, int csk)
{
    int printed = 0;

    for (int i = 0; i < WEB_CLIENT_MAX; i++)
    {
        if (web->clients[i].fd == csk)
        {
            printf ("http: del client fd[%d]=%d\n", i, csk);
            close (web->clients[i].fd);

            web->clients[i].fd = -1;
            web->clients[i].events = 0;
            web->streaming &= ~(1 << i);
            web->client_count--;
            break;
        }
    }

#if 0
    printf ("Web Clients (count=%d)\n", web->client_count);
    for (int i = 0; i < WEB_CLIENT_MAX; i++)
    {
        if (printed == web->client_count)
            break;

        printf (" [%d] .fd=%d .streaming=%d\n", i, web->clients[i].fd, !!(web->streaming & (1 << i)));

        if (web->clients[i].fd > 0)
            printed++;
    }
#endif
}

static char *
parse_header (char *req, size_t reqlen, char *hdr, char *buf, size_t buflen)
{
    char line[1024] = {};
    char *p = line;
    char *val = NULL;

    for (int i = 0; i < reqlen; i++)
    {
        p += sprintf (p, "%c", req[i]);

        if (req[i] == 0x0A)
        {
            if (strstr (line, hdr))
            {
                val = strtok (line, ":");
                val = strtok (NULL, "\r\n");
                if (val)
                {
                    /* eat any whitespace */
                    while (*val++)
                    {
                        if (is_ascii (*val))
                            break;
                    }

                    snprintf (buf, buflen, "%s", val);
                    printf ("Found header: [%s] -> [%s]\n", hdr, val);
                    break;
                }
            }

            p = line;
        }
    }

    return NULL;
}

struct hash_data
{
    u32 key;
    char *key_str;
    char *val;
};

struct hash_table
{
    struct hash_data items[256];
};

static void
hash_init (struct hash_table *t)
{
    memset (t, 0, sizeof (struct hash_table));
}

static void
hash_add_str (struct hash_table *t, char *key_str, char *val)
{
    u32 hash = hash_str (key_str);
    u8 key = hash % 255;
    struct hash_data *data = &t->items[key];

    if (data->key != 0)
    {
        printf ("hash: collsision!\n");
        printf (" existing: key=%x('%s') val='%s'\n", data->key, data->key_str, data->val);
        printf ("      new: key=%x('%s') val='%s'\n", key, key_str, val);
    }
    else
    {
        data->key = key;
        data->key_str = strdup (key_str);
        data->val = strdup (val);
    }
}

static char *
hash_lookup (struct hash_table *t, char *key_str)
{
    u32 hash = hash_str (key_str);
    u8 key = hash % 255;
    struct hash_data *data = &t->items[key];

    return data ? data->val : NULL;
}

static void
hash_free (struct hash_table *t)
{
    for (int i = 0; i < ARRAY_LEN (t->items); i++)
    {
        struct hash_data *data = &t->items[i];

        if (data->key != 0)
        {
            if (data->key_str) { free (data->key_str); }
            if (data->val) { free (data->val); }
            data->key = 0;
        }
    }
}

static void
parse_http_req (char *buf, int len, struct hash_table *table)
{
    char payload[256];
    char line[256];
    char *p = line;
    struct buffer b;

    buf_init (&b, payload, sizeof (payload));
    // printf ("----- parsing headers -----\n");

    for (int i = 0; i < len; i++)
    {
        char c = buf[i];

        p += sprintf (p, "%c", c);

        if (buf[i] == 0x0A)
        {
            p = line;

            // printf ("line: '%s'\n", line);

            if (strstr (line, "HTTP/1.1"))
            {
                char *start = strtok (line, "\r\n");

                hash_add_str (table, "start", start);
            }
            else if (strstr (line, ":"))
            {
                char *key = strtok (line, ":");
                char *val = strtok (NULL, "\r\n");

                while (*val++) { if (is_ascii (*val)) { break; } };

                hash_add_str (table, key, val);
            }
            else
            {
                buf_add_str (&b, line);
            }
        }
    }

    if (p != line)
    {
        buf_add_str (&b, line);
    }

    char *val = b.data;

    while (*val++) { if (is_ascii (*val)) { break; } };
    hash_add_str (table, "payload~", val);

    // printf ("----- parsing done --------\n");
}

static char big_buf[1024 * 1024 * 1]; // 1 Mb
static char send_buf[1024 * 1024 * 2]; // 2 Mb

int
http_read (struct web_server *web, int csk)
{
    char buf[64 * 1024] = {};
    int nread;

    nread = read (csk, buf, sizeof (buf));
    if (nread < 0)
    {
        printf ("read():%d on=%d failed: errno=%d '%s'\n", nread, csk, errno, strerror (errno));
        web_client_del (web, csk);
        return nread;
    }
    else if (nread == 0)
    {
        printf ("read():%d on=%d not quite right? only 0 bytes\n", nread, csk);
        web_client_del (web, csk);
        return nread;
    }

#if 1
    printf ("<------------HTTP RECV ----------------\n");
    printf ("%s\n", buf);
    printf ("<--------------------------------------\n");
    // hex_dump ((u8 *) buf, nread);
#endif

    struct hash_table table;

    hash_init (&table);
    parse_http_req (buf, nread, &table);

    printf ("<--- parsed headers ---\n");
    for (int i = 0; i < ARRAY_LEN (table.items); i++)
    {
        struct hash_data *d = &table.items[i];

        if (d->key != 0)
        {
            printf ("hdr: %0x('%s'): '%s'\n", d->key, d->key_str, d->val);
        }
    }
    printf ("<------------------ ---\n");

    char *method = strtok (buf, " \t\r\n");
    char *uri = strtok (NULL, " \t");
    char *proto = strtok (NULL, " \t\r\n");
    char *agent = NULL;

    /**
     * Extract substring from header
     *
     * Given header: 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0'
     * Returns     : 'Windows NT'
     */
    char line[1024] = {};
    char *p = line;
    for (int i = 0; i < nread; i++)
    {
        p += sprintf (p, "%c", buf[i]);

        if (buf[i] == 0x0A)
        {
            if (strstr (line, "User-Agent: Mozilla"))
            {
                agent = strtok (line, "(");
                agent = strtok (NULL, ";");
                break;
            }
            else if (strstr (line, "curl"))
            {
                agent = "curl";
                break;
            }

            p = line;
        }
    }

    if (!agent)
        agent = "--";

    printf ("http: RECV [REQ] <- client='%s'(sk=%d): %s '%s'\n", agent, csk, method, uri);

    int send_len = 0;
    char *event_msg = NULL;

    if (strcmp (uri, "/") == 0 &&
        strcmp (method, "GET") == 0)
    {
        struct buffer sb;
        long datalen;
        char *data;

        data = read_file ("index.html", &datalen);
        sb = build_response (data, datalen, "text/html", send_buf, sizeof (send_buf));
        free (data);

        http_send (csk, sb.data, sb.len, "RSP");
    }
    else if (strcmp (uri, "/favicon.ico") == 0 &&
             strcmp (method, "GET") == 0)
    {
        struct buffer sb;
        long datalen;
        char *data;

        data = read_file ("favicon.ico", &datalen);
        sb = build_response (data, datalen, "text/x-icon", send_buf, sizeof (send_buf));
        free (data);

        http_send (csk, sb.data, sb.len, "RSP");
    }
    else if (strcmp (uri, "/play") == 0 &&
             strcmp (method, "POST") == 0)
    {
        // TODO: what do we send in the reponse here???
        // just 200 OK?

        char str[128] = {};
        char *payload = hash_lookup (&table, "payload~");

        char *p = strtok (payload, "id="); 
        printf ("payload: '%s'\n", p);
        u32 requested_id = strtoll (p, NULL, 10);

        // TODO: maybe send some sort of 'pending' state while we're waiting for the chromecast?
        snprintf (str, sizeof (str), "playing id=%u", requested_id);
        struct buffer b = build_response (str, strlen (str), "text/html", send_buf, sizeof (send_buf));
        http_send (csk, b.data, b.len, "RSP");

        buf_init (&b, send_buf, sizeof (send_buf));
        buf_add_str (&b, "{");
        track_update_build (&b, requested_id);
        buf_add_str (&b, "}");

        http_event_send (web, "update", b.data);
    }
    else if (strcmp (uri, "/test") == 0 &&
             strcmp (method, "GET") == 0)
    {
        char *data = "Off";

        struct buffer sb = build_response (data, strlen (data), "text/html", send_buf, sizeof (send_buf));

        http_send (csk, sb.data, sb.len, "RSP");
        http_event_send (web, NULL, "Clicked");

        event (EVENT_LAUNCH, NULL);
    }
    else if (strcmp (uri, "/events") == 0 &&
             strcmp (method, "GET") == 0)
    {
        struct buffer b;

        for (int i = 0; i < web->client_count; i++)
        {
            if (web->clients[i].fd == csk)
            {
                web->streaming |= (1 << i);
            }
        }

        http_event_send_start (csk);

        buf_init (&b, send_buf, sizeof (send_buf));
        buf_add_str (&b, "{");
        buf_add_str (&b, "\"version\": %u,", timestamp);
        track_list_build (&b);
        buf_add_str (&b, "}");

        http_event_send (web, "hello", b.data);
        http_event_send (web, NULL, app_state ());
    }
    else if (strstr (uri, "/movies"))
    {
        /**
         * GET /movies/sonic-3.mp4 HTTP/1.1
         * Host: 192.168.1.101:5001
         * Connection: keep-alive
         * User-Agent: Mozilla/5.0 (Linux; Android 8.0; Build/OPR2.170623.027.S16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.0 Safari/537.36 CrKey/1.56.500000 DeviceType/AndroidTV
         * Range: bytes=0-
         * Accept-Encoding: identity;q=1, *;q=0
         * Accept: *//*
         * Accept-Language: en-GB
         * CAST-DEVICE-CAPABILITIES: {"bluetooth_supported":false,"display_supported":true,"hi_res_audio_supported":false,"remote_control_input_supported":true,"touch_input_supported":false}
         *
         * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Connection
         * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range
         * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Encoding
         */

        char *file = "/mnt/usb/movies/sonic-3.mp4";
        char val[128] = {};
        char *p = NULL;
        parse_header (buf, nread, "Range", val, sizeof (val));
        long long int bytes = 0;
        p = strtok (val, "bytes="); 
        printf ("bytes: '%s'\n", p);
        long long int start = strtoll (p, NULL, 10);
        printf ("bytes requested: %lld\n", start);
#if 0
        {
            int fd = -1;
            int wr = 0;
            long fsize = 0;
            char *buf = send_buf;
            int len = sizeof (send_buf);

            fd = open (file, O_RDONLY | O_LARGEFILE);
            if (fd > 0)
            {
                off_t total_len = lseek (fd, 0, SEEK_END);
                if (total_len < 0)
                {
                    perror ("lseek END failed");
                }

                lseek (fd, start, SEEK_SET);

                long long int read_len = read (fd, big_buf, sizeof (big_buf));

                printf ("data len=%lld/%lld\n", start + read_len, total_len);
                if (read_len < 0)
                {
                    printf ("Failed to read file (errno=%d '%s')\n", errno, strerror (errno));
                }

                wr += snprintf (buf + wr, len - wr, "HTTP/1.1 206 Partial Content\r\n");
                wr += snprintf (buf + wr, len - wr, "Content-Type: %s\r\n", "video/mp4");
                wr += snprintf (buf + wr, len - wr, "Content-Range: bytes %lld-%lld/%lld\r\n", start, start + read_len, total_len);
                wr += snprintf (buf + wr, len - wr, "Content-Length: %lld\r\n", read_len);
                wr += snprintf (buf + wr, len - wr, "Accept-Ranges: bytes\r\n");

                wr += snprintf (buf + wr, len - wr, "\r\n");
                memcpy (buf + wr, big_buf, read_len);
                wr += read_len;
                wr += snprintf (buf + wr, len - wr, "\r\n");

                printf ("response len=%d\n", wr);

                close (fd);

                send_len = wr;
            }
            else
            {
                printf ("Failed to open file '%s' (errno=%d '%s')\n", file, errno, strerror (errno));
            }
        }

        http_send (csk, send_buf, send_len, "RSP");
#else
        {
                struct buffer sb;
                long long read_len;
                long long total_len;
                
                read_len = read_file_large (file, start, &total_len, big_buf, sizeof (big_buf));

                buf_init (&sb, send_buf, sizeof (send_buf));
                buf_add_str (&sb, "HTTP/1.1 206 Partial Content\r\n");
                buf_add_str (&sb, "Content-Type: %s\r\n", "video/mp4");
                buf_add_str (&sb, "Content-Range: bytes %lld-%lld/%lld\r\n", start, start + read_len, total_len);
                buf_add_str (&sb, "Content-Length: %lld\r\n", read_len);
                buf_add_str (&sb, "Accept-Ranges: bytes\r\n");
                buf_add_str (&sb, "\r\n");
                buf_add_bytes (&sb, big_buf, read_len);
                buf_add_str (&sb, "\r\n");

                http_send (csk, sb.data, sb.len, "RSP");
        }
#endif

    }
    else
    {
        printf ("ERROR: unhandled url/verb combination '%s' '%s'\n", uri, method);
    }

    hash_free (&table);
    return nread;
}

bool
http_listen_socket_setup (struct web_server *web)
{
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons (web->port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    int opt = 1;
    int sk = -1;
    bool ok = false;

    if ((sk = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror ("Failed to open socket");
    }
    else if (setsockopt (sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt)) != 0)
    {
        perror ("Failed to set SO_REUSEADDR");
    }
    else if (bind (sk, (struct sockaddr *) &server_addr, sizeof (server_addr)) != 0)
    {
        perror ("Failed to bind socket");
    }
    else if (listen (sk, 32) != 0)
    {
        perror ("Failed to listen on socket");
    }
    else
    {
        web->listen_sk = sk;
        ok = true;
        // enqueue (HTTP_SEND_KA, 10000);
    }

    if (!ok)
    {
        close (sk);
    }

    return ok;
}

bool
http_init (struct web_server *web, struct pollfd *clients, u16 port)
{
    bool ok;

    web->port = port;
    web->clients = clients;
    for (int i = 0; i < WEB_CLIENT_MAX; i++)
    {
        web->clients[i].fd = -1;
    }

    ok = http_listen_socket_setup (web);
    if (!ok)
    {
        printf ("Failed to setup HTTP socket\n");
    }

    timestamp = time (NULL);

    printf ("timestamp: %u\n", timestamp);

    return ok;
}

