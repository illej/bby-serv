#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "app.h"
#include "util.h"
#include "web.h"
#include "event.h"

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static int
build_response (char *data, size_t datalen, char *mime, char *buf, size_t buflen)
{
    int wr = 0;

    wr += snprintf (buf + wr, buflen - wr, "HTTP/1.1 200 OK\r\n");
    wr += snprintf (buf + wr, buflen - wr, "Content-Type: %s\r\n", mime);
    wr += snprintf (buf + wr, buflen - wr, "Content-Length: %ld\r\n", datalen);
    wr += snprintf (buf + wr, buflen - wr, "\r\n");
    memcpy (buf + wr, data, datalen);
    wr += datalen;
    wr += snprintf (buf + wr, buflen - wr, "\r\n");

    return wr;
}

static int
build_response_from_file (char *file, char *mime, char *buf, size_t len)
{
    FILE *fp;
    int wr = 0;
    long fsize = 0;
    char *data;

    fp = fopen (file, "r");
    if (fp)
    {
        fseek (fp, 0, SEEK_END);
        fsize = ftell (fp);
        fseek (fp, 0, SEEK_SET);

        data = malloc (fsize + 1);
        fread (data, fsize, 1, fp);
        data[fsize] = 0;

        //        printf ("data len=%ld\n", fsize);

        wr += snprintf (buf + wr, len - wr, "HTTP/1.1 200 OK\r\n");
        wr += snprintf (buf + wr, len - wr, "Content-Type: %s\r\n", mime);
        wr += snprintf (buf + wr, len - wr, "Content-Length: %ld\r\n", fsize);
        wr += snprintf (buf + wr, len - wr, "\r\n");
        memcpy (buf + wr, data, fsize);
        wr += fsize;
        wr += snprintf (buf + wr, len - wr, "\r\n");

        //        printf ("response len=%d\n", wr);

        fclose (fp);
        free (data);
    }
    else
    {
        printf ("Failed to open file '%s'\n", file);
    }

    return wr;
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
}

void
http_event_send (struct web_server *web, char *msg)
{
    struct sigaction newact, oldact;
    char send_buf[66535] = {};

    char hdr[] =
        "HTTP/1.1 200 OK\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache, private\r\n";
    int send_len = 0;

    //    send_len += snprintf (send_buf + send_len, sizeof (send_buf) - send_len, "%s", hdr);
    //    send_len += snprintf (send_buf + send_len, sizeof (send_buf) - send_len, "\r\n");
    send_len += snprintf (send_buf + send_len, sizeof (send_buf) - send_len, "%x\r\ndata: %s\n\n", strlen (msg) + 8, msg);
    send_len += snprintf (send_buf + send_len, sizeof (send_buf) - send_len, "\r\n");

#if 0
    char line[512] = {};
    char *p = line;
    printf ("http: sending:\n");
    for (int i = 0; i < send_len; i++)
    {
        if ((i % 32) == 0 && i != 0)
        {
            printf ("%s\n", line);
            p = line;
        }

        p += sprintf (p, "%c", ascii_ (send_buf[i]));
    }

    if (p != line)
    {
        printf ("%s\n", line);
    }
#endif

    newact.sa_handler = SIG_IGN;
    sigemptyset (&newact.sa_mask);
    newact.sa_flags = 0;
    sigaction (SIGPIPE, &newact, &oldact);

    for (int i = 0; i < web->client_count; i++)
    {
        if (web->streaming & (1 << i))
        {
            http_send (web->clients[i].fd, send_buf, send_len, "EVT");
        }
    }

    sigaction (SIGPIPE, &oldact, NULL);
}

void
http_event_send_start (int csk)
{
    char hdr[] =
        "HTTP/1.1 200 OK\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "e\r\ndata: Hello!\n\n"
        "\r\n";
    int hdr_len = strlen (hdr);

#if 0
    char line[512] = {};
    char *p = line;
    for (int i = 0; i < hdr_len; i++)
    {
        if ((i % 32) == 0 && i != 0)
        {
            printf ("%s\n", line);
            p = line;
        }

        p += sprintf (p, "%c", ascii_ (hdr[i]));
    }

    if (p != line)
    {
        printf ("%s\n", line);
    }
#endif

    struct sigaction newact, oldact;
    newact.sa_handler = SIG_IGN;
    sigemptyset (&newact.sa_mask);
    newact.sa_flags = 0;
    sigaction (SIGPIPE, &newact, &oldact);

    http_send (csk, hdr, hdr_len, "EVT");

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

                // printf ("http: added client fd[%d]=%d\n", i, sk);
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
parse_header (char *buf, size_t buflen, char *hdr, char *value, size_t value_len)
{
    char line[1024] = {};
    char *p = line;
    char *val = NULL;

    for (int i = 0; i < buflen; i++)
    {
        p += sprintf (p, "%c", buf[i]);

        if (buf[i] == 0x0A)
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

                    snprintf (value, value_len, "%s", val);
                    printf ("Found header: [%s] -> [%s]\n", hdr, val);
                    break;
                }
            }

            p = line;
        }
    }

    return NULL;
}

static char big_buf[1024 * 1024 * 1]; // 1 Mb
static char send_buf[1024 * 1024 * 2]; // 2 Mb

int
http_read (struct web_server *web, int csk)
{
    char buf[65535] = {};
    int nread;

    nread = read (csk, buf, sizeof (buf));
    if (nread < 0)
    {
        printf ("read() on=%d failed: errno=%d '%s'\n", csk, errno, strerror (errno));
        web_client_del (web, csk);
        return nread;
    }
    else if (nread == 0)
    {
        printf ("read() on=%d not quite right? only 0 bytes\n", csk);
        web_client_del (web, csk);
        return nread;
    }

#if 1
    printf ("-------------HTTP Request--------------\n");
    printf ("%s\n", buf);
    printf ("---------------------------------------\n");
    // hex_dump ((u8 *) buf, nread);
#endif

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
        send_len = build_response_from_file ("index.html", "text/html", send_buf, sizeof (send_buf));
        http_send (csk, send_buf, send_len, "RSP");
    }
    else if (strcmp (uri, "/favicon.ico") == 0 &&
             strcmp (method, "GET") == 0)
    {
        send_len = build_response_from_file ("favicon.ico", "image/x-icon", send_buf, sizeof (send_buf));
        http_send (csk, send_buf, send_len, "RSP");
    }
    else if (strcmp (uri, "/play") == 0 &&
             strcmp (method, "POST") == 0)
    {
        char *data = "Playing!";
        send_len = build_response (data, strlen (data), "text/html", send_buf, sizeof (send_buf));

        http_send (csk, send_buf, send_len, "RSP");
    }
    else if (strcmp (uri, "/test") == 0 &&
             strcmp (method, "GET") == 0)
    {
        char *data = "Off";

        send_len = build_response (data, strlen (data), "text/html", send_buf, sizeof (send_buf));

        http_send (csk, send_buf, send_len, "RSP");
        http_event_send (web, "Clicked");

        event (EVENT_LAUNCH, NULL);
    }
    else if (strcmp (uri, "/events") == 0 &&
             strcmp (method, "GET") == 0)
    {
        for (int i = 0; i < web->client_count; i++)
        {
            if (web->clients[i].fd == csk)
            {
                web->streaming |= (1 << i);
            }
        }
        // printf ("http: client:%d streaming:0b%b\n", csk, web->streaming);

        http_event_send_start (csk);
        http_event_send (web, app_state ());
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

        char val[128] = {};
        char *p = NULL;
        parse_header (buf, nread, "Range", val, sizeof (val));
        long long int bytes = 0;
        p = strtok (val, "bytes="); 
        printf ("bytes: '%s'\n", p);
        long long int start = strtoll (p, NULL, 10);
        printf ("bytes requested: %lld\n", start);
        {
            int fd = -1;
            int wr = 0;
            long fsize = 0;
            char *file = "/mnt/usb/movies/sonic-3.mp4";
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
    }
    else
    {
        printf ("ERROR: unhandled url/verb combination '%s' '%s'\n", uri, method);
    }

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

    return ok;
}

