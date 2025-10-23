#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdbool.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/time.h>
#include <errno.h>


#include <poll.h>
#include <dirent.h>

#include <signal.h>
#include <execinfo.h>


#include "app.h"
#include "util.h"
#include "event.h"

#include "discovery.h"
#include "discovery.c"

#include "web.h"
#include "cast.h"

struct
{
    struct web_server web;

    struct pollfd pfds[MAX_FD];
    int mdns_sk;
    int ssl_sk;
    SSL *ssl;
    char chromecast_ip[INET6_ADDRSTRLEN];
    int state;
    struct delayed_msg queue[32];
} app = {};

static struct action fsm[STATE_MAX][EVENT_MAX] = {
    [STATE_INIT]       [EVENT_SEARCH]    = { action_search,  STATE_SEARCHING  },
    [STATE_SEARCHING]  [EVENT_FOUND]     = { action_connect, STATE_CONNECTING },
    [STATE_CONNECTING] [EVENT_CONNECTED] = { action_status,  STATE_READY      },
    [STATE_CONNECTING] [EVENT_RESET]     = { action_search,  STATE_SEARCHING  },
};

char *
state_str (int state)
{
    char *str;

    switch (state)
    {
        case STATE_INIT: { str = "INIT"; } break;
        case STATE_SEARCHING: { str = "SEARCHING"; } break;
        case STATE_CONNECTING: { str = "CONNECTING"; } break;
        case STATE_CONNECTED: { str = "CONNECTED"; } break;
        case STATE_READY: { str = "READY"; } break;
        case STATE_PLAYING: { str = "PLAYING"; } break;
        default: { str = "??"; } break;
    }

    return str;
}

char *
app_state (void)
{
    return state_str (app.state);
}

char *
event_str (int event)
{
    char *str;

    switch (event)
    {
        case EVENT_ENABLE: { str = "ENABLE"; } break;
        case EVENT_SEARCH: { str = "SEARCH"; } break;
        case EVENT_FOUND: { str = "FOUND"; } break;
        case EVENT_RESET: { str = "RESET"; } break;
        case EVENT_CONNECTED: { str = "CONNECTED"; } break;
        case EVENT_TIMEOUT: { str = "TIMEOUT"; } break;
        case EVENT_PLAY: { str = "PLAY"; } break;
        case EVENT_STOP: { str = "STOP"; } break;
        default: { str = "??"; } break;
    }

    return str;
}

void
action_search (void *data)
{
    mdns_send (app.mdns_sk);
}

static char *
msg_str (struct delayed_msg *msg)
{
    char *str;

    switch (msg->type)
    {
        case TLS_SEND_PING: { str = "TLS-SEND-PING"; } break;
        case TLS_SEND_PONG: { str = "TLS-SEND-PONG"; } break;
        case HTTP_SEND_KA:  { str = "HTTP-SEND-KA";  } break;
        default:            { str = "??";            } break;
    }

    return str;
}

void
enqueue (int type, int delay)
{
    for (int i = 0; i < ARRAY_LEN (app.queue); i++)
    {
        struct delayed_msg *msg = &app.queue[i];

        if (!msg->pending)
        {
            msg->type = type;
            msg->delay = delay;
            msg->pending = true;
            msg->started_at = time_ms ();

            printf ("queue: added %s at %ld for %d ms\n", msg_str (msg), msg->started_at, msg->delay);
            return;
        }
    }

    printf ("queue: full\n");
}

void
action_connect (void *data)
{
    app.ssl = tls_socket_setup (&app.ssl_sk, (char *) data);
    if (!(app.ssl && app.ssl_sk > 0))
    {
        printf ("Failed to setup TLS socket\n");
        event (EVENT_RESET, NULL);
    }
    else
    {
        printf ("tls: ok\n");

        app.pfds[TLS_FD].fd = app.ssl_sk;
        app.pfds[TLS_FD].events = POLLIN;

        enqueue (TLS_SEND_PING, 0);
    }
}

void
action_status (void *data)
{
    tls_send_msg (app.ssl, receiver_ns, get_status_msg);
    tls_send_msg (app.ssl, receiver_ns, get_app_availability_msg);
}

void
event (int event, void *data)
{
    int old_state = app.state;
    int new_state;

    if (fsm[old_state][event].func)
    {
        new_state = fsm[old_state][event].new_state;

        printf ("event: %s state: %s -> %s\n", event_str (event), state_str (old_state), state_str (new_state));

        fsm[old_state][event].func (data);
        app.state = new_state;

        http_event_send (&app.web, state_str (app.state));
    }
}



struct movie
{
    u8 index;
    char *name;
};

static struct movie *movies;
static int movie_count;



/*
 * TODO:
 *  - actually control the player via "urn:x-cast:com.google.cast.media"
 *    See:
 *      https://developers.google.com/cast/docs/media/messages
 *      https://developers.google.com/cast/docs/media
 *
 * - do web server
 */




static bool
movie_list (void)
{
    const char *movie_dir = "/mnt/usb/movies";
    struct movie *movie;
    struct dirent *ent;
    DIR *dir;

    movie_count = 0;

    dir = opendir (movie_dir);
    if (dir)
    {
        printf ("Loading movies from '%s'\n", movie_dir);

        while ((ent = readdir (dir)))
        {
            if (ent->d_type & DT_REG)
            {
                movie_count++;

                movies = realloc (movies, sizeof (struct movie) * movie_count);

                movie = &movies[movie_count - 1];
                movie->index = movie_count - 1;
                movie->name = strdup (ent->d_name);
            }
        }
    }
    else
    {
        printf ("Failed to open directory '%s'. errno=%d '%s'\n", movie_dir, errno, strerror (errno));
    }

    return (movie_count > 0);
}

static void
signal_handler (int sig, siginfo_t *info, void *ucontext)
{
    fprintf (stderr, "Signal %d (%s)\n", sig, strsignal (sig));

    abort ();
}

static void
do_send (struct delayed_msg *msg)
{
    printf ("queue: do send %s\n", msg_str (msg));
    switch (msg->type)
    {
        case TLS_SEND_PING:
            tls_send_msg (app.ssl, heartbeat_ns, ping_msg);
            printf ("tls: -> PING\n");
            break;
        case TLS_SEND_PONG:
            tls_send_msg (app.ssl, heartbeat_ns, pong_msg);
            printf ("tls: -> PONG\n");
            break;
        case HTTP_SEND_KA:
            http_event_send (&app.web, ":keep-alive");
            enqueue (HTTP_SEND_KA, 10000);
            break;
    }

    msg->pending = false;
}

int
app_nfds (void)
{
    return WEB_CLIENT_FD_START + app.web.client_count;
}

static long
process_timers (void)
{
    long shortest_timeout = 20000;
    long now = time_ms ();

    for (int i = 0; i < ARRAY_LEN (app.queue); i++)
    {
        struct delayed_msg *msg = &app.queue[i];

        if (msg->pending)
        {
            long time_waited = now - msg->started_at;
            long remaining = msg->delay - time_waited;

            printf ("queue: %s has waited %ld/%ld ms\n", msg_str (msg), time_waited, msg->delay);

            if (remaining <= 0)
            {
                do_send (msg);
            }
            else if (remaining > 0 && remaining < shortest_timeout)
            {
                shortest_timeout = remaining;
            }
        }
    }

    printf ("queue: timeout: %ld ms\n", shortest_timeout);

    return shortest_timeout;
}

int
main (int c, char **v)
{
    struct sigaction act = {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_RESTART | SA_SIGINFO,
    };

    if (sigaction (SIGSEGV, &act, (struct sigaction *) NULL) != 0)
    {
        printf ("Failed to setup signal handler\n");
        return 1;
    }

    if (!movie_list ())
    {
        printf ("Failed to get movie list\n");
        return 1;
    }

    if ((app.mdns_sk = mdns_setup ()) == -1)
    {
        printf ("Failed to setup MDNS socket\n");
        return 1;
    }

    if (!http_init (&app.web, &app.pfds[WEB_CLIENT_FD_START], 5001))
    {
        return 1;
    }

    printf ("Baby's First Web Server\n");
    printf ("Listening on port %d\n", app.web.port);

    app.pfds[MDNS_FD].fd = app.mdns_sk;
    app.pfds[MDNS_FD].events = POLLIN;
    // app.pfds[TLS_FD].fd = app.ssl_sk;
    // app.pfds[TLS_FD].events = POLLIN;
    app.pfds[WEB_FD].fd = app.web.listen_sk;
    app.pfds[WEB_FD].events = POLLIN;

    int timeout = 5000;
    app.state = STATE_INIT;

    while (1)
    {
        printf ("app: %s\n", state_str (app.state));

        if (app.chromecast_ip[0] == '\0')
        {
            event (EVENT_SEARCH, NULL);
        }

        timeout = process_timers ();

        printf ("poll: nfds=%d timeout=%ld\n", app_nfds (), timeout);
        int ret = poll (app.pfds, MAX_FD, timeout);

        for (int i = 0; ret > 0 && i < MAX_FD; i++)
        {
            if (app.pfds[i].revents & POLLIN)
            {
                ret--;
                if (i == MDNS_FD)
                {
                    printf ("mdns: recv\n");
                    mdns_recv (app.pfds[MDNS_FD].fd);
                }
                else if (i == TLS_FD)
                {
                    printf ("tls: recv\n");
                    tls_read (app.ssl);
                }
                else if (i == WEB_FD)
                {
                    printf ("http: accept\n");
                    http_accept (&app.web);
                }
                else
                {
                    printf ("http: read from client(%d) fd=%d\n", i - WEB_CLIENT_FD_START, app.pfds[i].fd);
                    if (http_read (&app.web, app.pfds[i].fd) <= 0)
                    {
                        printf ("http-client(%d) closed\n", i - WEB_CLIENT_FD_START);
                    }
                }
            }
        }
    }

    close (app.pfds[MDNS_FD].fd);
    close (app.pfds[TLS_FD].fd);
    close (app.pfds[WEB_FD].fd);

    printf ("Exiting\n");
    return 0;
}
