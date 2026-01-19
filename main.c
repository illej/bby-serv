#define _FILE_OFFSET_BITS 64
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

#include "app.h"
#include "util.h"
#include "event.h"

#include "web.h"
#include "cast.h"
#include "discovery.h"

#ifdef UNITY_BUILD
#include "web.c"
#include "cast.c"
#include "discovery.c"
#endif


struct
{
    struct web_server web;

    struct pollfd pfds[MAX_FD];
    int mdns_sk;
    int ssl_sk;
    SSL *ssl;
    char chromecast_ip[INET6_ADDRSTRLEN];
    int state;
    char info[APP_INFO_LEN];

    // TODO: if we are only going to have one of each type in here
    //       at a time then maybe this should be a hash table?
    struct delayed_msg queue[32];
} app = {};

struct movie
{
    u8 index;
    char *name;
    u32 id;
    bool active;
};

struct track_list
{
    struct movie *items;
    int count;
    u32 active_id;
};

static struct track_list tracks;
static struct action fsm[STATE_MAX][EVENT_MAX] = {
    [STATE_INIT]       [EVENT_RESET]     = { action_reset,   STATE_INIT        },
    [STATE_INIT]       [EVENT_FOUND]     = { action_connect, STATE_CONNECTING  },
    [STATE_CONNECTING] [EVENT_CONNECTED] = { action_status,  STATE_READY       },
    [STATE_CONNECTING] [EVENT_RESET]     = { action_reset,   STATE_INIT        },
    [STATE_READY]      [EVENT_LAUNCH]    = { action_launch,  STATE_CONTROLLING },
    [STATE_READY]      [EVENT_UPDATE]    = { action_update,  STATE_READY       },
    [STATE_CONTROLLING][EVENT_LOAD]      = { action_load,    STATE_LOADING     },
    [STATE_LOADING]    [EVENT_LOADED]    = { action_play,    STATE_PLAYING     },
    [STATE_LOADING]    [EVENT_RESET]     = { action_status,  STATE_CONTROLLING },
};

/*
 * TODO:
 * - navigating files is slow.. move them back into main.c?!
 * 
 * Control Flow (for now!):
 * - on startup, find & connect to chromecast
 * - user selects movie via web app
 * - launch Default Media App, connect to Default Media App, load movie
 * - implement movie status & play/pause/stop
 * - when movie stops, close Default Media App
 *
 * > rework html and implement /play POST endpoint
 *
 *
 * - clean up state machine
 * - figure out manifest & dynamic reloading (inotify)
 * - movie list in memory, id hashes etc
 * - sending sync & update messages to web clients
 * - consolidate http resp/req/event message construction
 * - web client page reloading on version change
 * - figure out html styling, can we resize/reshape list items?
 * - send email on crash or critical error
 * - fixup http req string parsing
 */


char *
app_state (void)
{
    return state_str (app.state);
}

void
action_reset (void *data)
{
    memset (app.chromecast_ip, 0, sizeof (app.chromecast_ip));
    mdns_send (app.mdns_sk);
    enqueue (RESET, 20000);
}

static char *
msg_str (struct delayed_msg *msg)
{
    char *str;

    switch (msg->type)
    {
        case RESET:         { str = "RESET";         } break;
        case TLS_SEND_PING: { str = "TLS-SEND-PING"; } break;
        case TLS_SEND_PONG: { str = "TLS-SEND-PONG"; } break;
        case HTTP_SEND_KA:  { str = "HTTP-SEND-KA";  } break;
        default:            { str = "??";            } break;
    }

    return str;
}

void
timer_cancel (int type)
{
    for (int i = 0; i < ARRAY_LEN (app.queue); i++)
    {
        struct delayed_msg *msg = &app.queue[i];

        if (msg->type == type && msg->pending)
        {
            msg->pending = false;
//             printf ("queue: cancelled %s\n", msg_str (msg));
        }
    }
}

void
enqueue (int type, int delay)
{
    timer_cancel (type);

    for (int i = 0; i < ARRAY_LEN (app.queue); i++)
    {
        struct delayed_msg *msg = &app.queue[i];

        if (!msg->pending)
        {
            msg->type = type;
            msg->delay = delay;
            msg->pending = true;
            msg->started_at = time_ms ();

//            printf ("queue: added %s at %ld for %d ms\n", msg_str (msg), msg->started_at, msg->delay);
            return;
        }
    }

    printf ("queue: full\n");
}

void
action_connect (void *data)
{
    timer_cancel (RESET);

    app.ssl = tls_socket_setup (&app.ssl_sk, (char *) data);
    if (!(app.ssl && app.ssl_sk > 0))
    {
        printf ("Failed to setup TLS socket\n");

        event (EVENT_RESET, NULL);
    }
    else
    {
        // printf ("tls: ok\n");

        snprintf (app.chromecast_ip, sizeof (app.chromecast_ip), data);

        app.pfds[TLS_FD].fd = app.ssl_sk;
        app.pfds[TLS_FD].events = POLLIN;

        enqueue (TLS_SEND_PING, 0);
        enqueue (RESET, 10000);
    }
}

void
action_status (void *data)
{
    tls_send_msg (app.ssl, receiver_ns, get_status_msg, "receiver-0");
    // TODO: not really needed as it just seems to confirm the Default Media
    // App is present on the chromecast, it may indicate if something else is
    // using the app, but that will need testing.
    //
    // tls_send_msg (app.ssl, receiver_ns, get_app_availability_msg);
}

void
action_launch (void *data)
{
    tls_send_msg (app.ssl, receiver_ns, launch_msg, "receiver-0");
}

void
action_load (void *data) // TODO: this is actually connect-to-app
{
    char *destination_id = data;
    char msgstr[1024] = {};

    snprintf (msgstr, sizeof (msgstr), "{\"type\": \"LOAD\", \"requestId\": 17, \"media\": {\"contentId\": \"%s\", \"streamType\": \"BUFFERED\", \"contentType\": \"%s\"}}", "http://192.168.1.101:5001/movies/sonic-3.mp4", "video/mp4");

    tls_send_msg (app.ssl, media_ns, msgstr, destination_id);
}

void
action_play (void *data)
{
    // tls_send_msg (app.ssl, receiver_ns, launch_msg, "receiver-0");
}

void
action_update (void *data)
{
    memset (app.info, 0, sizeof (app.info));

    if (data)
    {
        snprintf (app.info, sizeof (app.info), "%s", data);
    }
}

static char *
state_msg (char *buf, size_t len)
{
    if (app.info[0] != '\0')
    {
        snprintf (buf, len, "%s (%s)", state_str (app.state), app.info);
    }
    else
    {
        snprintf (buf, len, "%s", state_str (app.state));
    }

    return buf;
}

void
event (int event, void *data)
{
    int old_state = app.state;
    int new_state;
    char msg[1024] = {};

    if (fsm[old_state][event].func)
    {
        new_state = fsm[old_state][event].new_state;

        printf ("event: %s state: %s -> %s\n", event_str (event), state_str (old_state), state_str (new_state));

        fsm[old_state][event].func (data);
        app.state = new_state;

        http_event_send (&app.web, NULL, state_msg (msg, sizeof (msg)));
    }
    else
    {
        // printf ("IGNORED event: %s in state: %s\n", event_str (event), state_str (old_state));
    }
}

static bool
movie_list (void)
{
    const char *movie_dir = "/mnt/usb/movies"; // TODO: get this from a config file
    struct movie *movie;
    struct dirent *ent;
    DIR *dir;

    tracks.count = 0;

    dir = opendir (movie_dir);
    if (dir)
    {
        printf ("Loading movies from '%s'\n", movie_dir);

        while ((ent = readdir (dir)))
        {
            if (ent->d_type & DT_REG)
            {
                tracks.count++;

                tracks.items = realloc (tracks.items, sizeof (struct movie) * tracks.count);

                movie = &tracks.items[tracks.count - 1];
                movie->index = tracks.count - 1;
                movie->name = strdup (ent->d_name);
                movie->id = hash_str (movie->name);
            }
        }
    }
    else
    {
        printf ("Failed to open directory '%s'. errno=%d '%s'\n", movie_dir, errno, strerror (errno));
    }

    return (tracks.count > 0);
}

void
track_list_build (struct buffer *b)
{
    buf_add_str (b, "\"track-list\": [");

    for (int i = 0; i < tracks.count; i++)
    {
        struct movie *t = &tracks.items[i];

        buf_add_str (b, "{\"name\": \"%s\", \"id\": %u", t->name, t->id);
        if (t->active)
        {
            buf_add_str (b, ", \"active\": true");
        }
        buf_add_str (b, "}");

        if (i != (tracks.count - 1))
        {
            buf_add_str (b, ",");
        }
    }

    buf_add_str (b, "]");
}

// requested_id = 0 to turn all off
void
track_update_build (struct buffer *b, u32 requested_id)
{
    bool first = true;
    int count = 0;
    int stop_at = requested_id > 0 && tracks.active_id > 0 ? 2 : 1;

    buf_add_str (b, "\"track-list\": [");
    for (int i = 0; i < tracks.count; i++)
    {
        struct movie *t = &tracks.items[i];

        if ((t->active && t->id != requested_id) ||
            (!t->active && t->id == requested_id))
        {
            t->active = !t->active;

            buf_add_str (b, "{\"id\": %u, \"active\": %s}", t->id, t->active ? "true" : "false");

            if (++count != stop_at)
            {
                buf_add_str (b, ",");
            }
        }
    }
    buf_add_str (b, "]");

    tracks.active_id = requested_id;
}

static void
do_send (struct delayed_msg *msg)
{
    // printf ("queue: do send %s\n", msg_str (msg));
    switch (msg->type)
    {
        case RESET:
            event (EVENT_RESET, NULL);
            break;
        case TLS_SEND_PING:
            tls_send_msg (app.ssl, heartbeat_ns, ping_msg, "receiver-0");
            // printf ("tls: -> PING\n");
            break;
        case TLS_SEND_PONG:
            tls_send_msg (app.ssl, heartbeat_ns, pong_msg, "receiver-0");
            // printf ("tls: -> PONG\n");
            break;
        case HTTP_SEND_KA:
            http_event_send (&app.web, NULL, ":keep-alive");
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

//            printf ("queue: %s has waited %ld/%ld ms\n", msg_str (msg), time_waited, msg->delay);

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

//    printf ("queue: timeout: %ld ms\n", shortest_timeout);

    return shortest_timeout;
}

int
main (int c, char **v)
{
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

    app.state = STATE_INIT;
    event (EVENT_RESET, NULL);

    while (1)
    {
        int timeout = process_timers ();

        // printf ("[%.3f] app: %s (poll nfds=%d timeout=%ld)\n", ((float) time_ms ()) / 1000.0f, app_state (), app_nfds (), timeout);
        int ret = poll (app.pfds, MAX_FD, timeout);

        for (int i = 0; ret > 0 && i < MAX_FD; i++)
        {
            if (app.pfds[i].revents & POLLIN)
            {
                ret--;
                if (i == MDNS_FD)
                {
                    // printf ("mdns: recv\n");
                    mdns_recv (app.pfds[MDNS_FD].fd);
                }
                else if (i == TLS_FD)
                {
                    // printf ("tls: recv\n");
                    tls_read (app.ssl);
                }
                else if (i == WEB_FD)
                {
                    // printf ("http: accept\n");
                    http_accept (&app.web);
                }
                else
                {
                    // printf ("http: read from client(%d) fd=%d\n", i - WEB_CLIENT_FD_START, app.pfds[i].fd);
                    if (http_read (&app.web, app.pfds[i].fd) <= 0)
                    {
                        // printf ("http-client(%d) closed\n", i - WEB_CLIENT_FD_START);
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
