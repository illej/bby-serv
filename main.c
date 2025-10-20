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

#include <pb_encode.h>
#include <pb_decode.h>
#include "cast_channel.pb.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <tiny-json.h>

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
#include "web.c"


struct delayed_msg
{
    enum {
        TLS_SEND_PING,
        TLS_SEND_PONG,
        HTTP_SEND_KA,
    } type;
    int delay;
    bool pending;
    long started_at;
};

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

static const char *connection_ns = "urn:x-cast:com.google.cast.tp.connection";
static const char *heartbeat_ns = "urn:x-cast:com.google.cast.tp.heartbeat";
static const char *receiver_ns = "urn:x-cast:com.google.cast.receiver";
static const char *connect_msg = "{\"type\": \"CONNECT\"}";
static const char *ping_msg = "{\"type\": \"PING\"}";
static const char *pong_msg = "{\"type\": \"PONG\"}";
static const char *get_status_msg = "{\"type\": \"GET_STATUS\", \"requestId\": 17}";
static const char *get_app_availability_msg = "{\"type\": \"GET_APP_AVAILABILITY\", \"requestId\": 17, \"appId\": [\"CC1AD845\"]}";
static const char *launch_msg ="{\"type\": \"LAUNCH\", \"requestId\": 17, \"appId\": \"CC1AD845\"}";


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

static bool
encode_string (pb_ostream_t *stream, const pb_field_iter_t *field, void * const *arg)
{
    const char *str = (const char *) (*arg);

    if (pb_encode_tag_for_field (stream, field))
        return pb_encode_string (stream, (unsigned char *) str, strlen (str));

    return false;
}

/*
 * https://jpa.kapsi.fi/nanopb/docs/concepts.html#decoding-callbacks
 */
static bool
decode_string (pb_istream_t *stream, const pb_field_iter_t *field, void **arg)
{
    if (field && PB_LTYPE (field->type) == PB_LTYPE_STRING)
    {
        *arg = malloc (stream->bytes_left + 1);
        memset (*arg, 0, stream->bytes_left + 1);

        return pb_read (stream, *arg, stream->bytes_left);
    }

    return false;
}


static bool
send_msg (SSL *ssl, const char *namespace, const char *payload)
{
    static uint8_t send_buf[4094];
    size_t send_len = sizeof (send_buf);
    extensions_api_cast_channel_CastMessage msg = extensions_api_cast_channel_CastMessage_init_zero;
    pb_ostream_t stream;
    size_t wr;
    bool ok ;

    memset (send_buf, 0, send_len);

    stream = pb_ostream_from_buffer (send_buf + 4, send_len - 4);

    msg.protocol_version = extensions_api_cast_channel_CastMessage_ProtocolVersion_CASTV2_1_0;
    msg.source_id.arg = (void *) "sender-0";
    msg.source_id.funcs.encode = encode_string;
    msg.destination_id.arg = (void *) "receiver-0";
    msg.destination_id.funcs.encode = encode_string;
    msg.namespace.arg = (void *) namespace;
    msg.namespace.funcs.encode = encode_string;
    msg.payload_type = extensions_api_cast_channel_CastMessage_PayloadType_STRING;
    msg.payload_utf8.arg = (void *) payload;
    msg.payload_utf8.funcs.encode = encode_string;

    ok = pb_encode (&stream, extensions_api_cast_channel_CastMessage_fields, &msg);
    if (ok)
    {
        send_buf[0] = (stream.bytes_written >> 24) & 0xFF;
        send_buf[1] = (stream.bytes_written >> 16) & 0xFF;
        send_buf[2] = (stream.bytes_written >>  8) & 0xFF;
        send_buf[3] = (stream.bytes_written >>  0) & 0xFF;

        ok = SSL_write_ex (ssl, send_buf, stream.bytes_written + 4, &wr);
        if (ok)
        {
//            hex_dump (send_buf, wr);
        }
    }

    if (!ok)
    {
        printf ("tls: send failed\n");
    }

    return ok;
}

/*
 * https://docs.openssl.org/3.3/man7/ossl-guide-tls-client-block
 */
static SSL *
tls_socket_setup (int *out_sk, char *ip)
{
    struct sockaddr_in addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    int sk;
    bool ok;

    printf ("tls: socket setup\n");
    
    SSL_library_init ();
    SSL_load_error_strings ();

    sk = socket (AF_INET, SOCK_STREAM, 0);
    printf ("tls: socket=%d\n", sk);
    if (sk > -1)
    {
        addr.sin_family = AF_INET;
        addr.sin_port = htons (8009);
        inet_pton (AF_INET, ip, &addr.sin_addr);

        printf ("tls: connecting with %s\n", ip);
        if (connect (sk, (struct sockaddr *) &addr, sizeof (addr)) == 0)
        {
            ctx = SSL_CTX_new (TLS_client_method ());
            if (ctx)
            {
                /* The chromecast has a self-signed cert so we
                 * skip verification */
                SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);
                SSL_CTX_set_default_verify_paths (ctx); // TODO: probably don't need this then?
                SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);

                ssl = SSL_new (ctx);
                if (!ssl)
                    goto out;

                bio = BIO_new (BIO_s_socket ());
                if (!bio)
                    goto out;

                BIO_set_fd (bio, sk, BIO_CLOSE);
                SSL_set_bio (ssl, bio, bio);

                int ret = SSL_connect (ssl);
                if (ret != 1)
                    goto out;

                printf ("tls: SSL connect: %d\n", ret);

                *out_sk = sk;

                ok = send_msg (ssl, connection_ns, connect_msg);
                if (ok)
                {
#if 0
                    ok = send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_status_msg);
                    printf ("TLS: send GET_STATUS: %s\n", ok ? "OK" : "Failed");
#endif

                }
                else
                {
                    printf ("Failed to send message to chromecast\n");
                }
            }
            else
            {
                perror ("Failed to create SSL context");
            }
        }
        else
        {
            printf ("Failed to connect to server %s\n", app.chromecast_ip);
        }
    }
    else
    {
        perror ("Failed to open socket\n");
    }

    printf ("tls: setup: %s\n", ok ? "OK" : "Failed");
out:
    return ssl;
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

static void
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
    printf ("TODO: check chromecast status\n");
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


#define OPENSSL_DUMP_ERR() \
    do { \
        int err; \
        while ((err = ERR_get_error ())) \
        { \
            printf ("OpenSSL Error: %s\n", ERR_error_string (err, NULL)); \
        } \
    } while (0)









static void
json_dump (json_t const *json, int indent)
{
    json_t const* child;
    jsonType_t const type = json_getType (json);

    if (type != JSON_OBJ && type != JSON_ARRAY) {
        printf ("Can't dump json\n");
        return;
    }

    printf ("%s\n", type == JSON_OBJ? "{": "[");

    indent++;

    for(child = json_getChild (json); child != 0; child = json_getSibling (child))
    {
        jsonType_t propertyType = json_getType (child);
        char const* name = json_getName (child);

        if (name)
        {
            printf ("%*s\"%s\": ", indent * 4, "", name);
        }

        if (propertyType == JSON_OBJ || propertyType == JSON_ARRAY)
        {
            if (type == JSON_ARRAY)
            {
                printf ("%*s", indent * 4, "");
            }

            json_dump (child, indent);
        }
        else
        {
            char const *value = json_getValue (child);
            if (value)
            {
                bool const text = JSON_TEXT == json_getType (child);
                char const* fmt = text ? "\"%s\"" : "%s";

                printf (fmt, value);
            }
        }

        bool const last = !json_getSibling (child);
        if (last)
            printf ("\n");
        else
            printf (",\n");
    }

    indent--;

    printf ("%*s%s", indent * 4, "", type == JSON_OBJ? "}": "]");

    if (indent == 0)
    {
        printf ("\n");
    }
}


/**
 * CASTv2 protocol description: docs.rs/crate/gcast/latest/source/PROTOCOL.md
 */



enum wire_type
{
    VARINT = 0,
    I64,
    LEN,
    SGROUP,
    EGROUP,
    I32
};

static char *
wire_str (u8 wire)
{
    char *str;

    switch (wire)
    {
        case VARINT: { str = "VARINT"; } break;
        case I64:    { str = "I64";    } break;
        case LEN:    { str = "LEN";    } break;
        case SGROUP: { str = "SGROUP"; } break;
        case EGROUP: { str = "EGROUP"; } break;
        case I32:    { str = "I32";    } break;
        default:     { str = "??";     } break;
    }

    return str;
}

static char *
field_str (u8 fieldno)
{
    char *str;

    // TODO: replace raw ints with extensions_api_cast_channel_CastMessage_*_tag (maybe..)
    switch (fieldno)
    {
        case 1:  { str = "protocol-version"; } break;
        case 2:  { str = "source-id";        } break; 
        case 3:  { str = "destination-id";   } break;
        case 4:  { str = "namespace";        } break;
        case 5:  { str = "payload-type";     } break;
        case 6:  { str = "payload-utf8";     } break;
        case 7:  { str = "payload-binary";   } break;
        default: { str = "??";               } break;
     }

     return str;
}

struct tag
{
    u8 fieldno;
    u8 wire;
};

static int
decode_varint (u8 *buf, u64 *varint)
{
    int bytes = 0;

    for (int i = 0; i < 10; i++)
    {
        u8 b = buf[i];

        *varint |= (u64) (b & 0x7F) << (i * 7);
        bytes++;

        if ((b & 0x80) == 0)
            break;
    }

    return bytes;
}

static int
decode_tag (u8 *buf, size_t len, struct tag *tag)
{
    u64 varint = 0;
    int bytes = 0;

    bytes += decode_varint (buf, &varint);

    tag->fieldno = varint >> 3;
    tag->wire = varint & 0x07;

    return bytes;
}

static void
parse_recv_msg (u8 *buf, size_t len, SSL *ssl)
{
    extensions_api_cast_channel_CastMessage rmsg = extensions_api_cast_channel_CastMessage_init_zero;

    rmsg.source_id.funcs.decode = decode_string;
    rmsg.destination_id.funcs.decode = decode_string;
    rmsg.namespace.funcs.decode = decode_string;
    rmsg.payload_utf8.funcs.decode = decode_string;

    uint32_t rlen = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + (buf[3] << 0);
    buf += 4;
    len -= 4;

    /**
     * https://protobuf.dev/programming-guides/encoding/
     *
     * Field numbers (defined by cast_channel.proto):
     * 1 = protocol-version
     * 2 = source_id
     * 3 = destination_id
     * 4 = namespace
     * 5 = payload_type
     * 6 = payload_utf8
     * 7 = payload_binary
     *
     * Wire-type:
     * 0 = VARINT
     * 1 = I64
     * 2 = LEN
     * 3 = SGROUP
     * 4 = EGROUP
     * 5 = I32
     *
     * Tag:
     *   (field_number << 3) | wire_type
     * 
     * 0000 1000
     */

    int bytes = 0;
    while (bytes < len)
    {
        struct tag tag = {};
        u64 varint = 0;

        bytes += decode_tag (buf + bytes, len - bytes, &tag);
        if (tag.wire == VARINT)
        {
            bytes += decode_varint (buf + bytes, &varint);
//            printf ("%d %s : %" PRIu64 "\n", tag.fieldno, field_str (tag.fieldno), varint);
        }
        else if (tag.wire == LEN)
        {
            bytes += decode_varint (buf + bytes, &varint);
 //           printf ("%d %s : %s(%" PRIu64 ") '%.*s'\n", tag.fieldno, field_str (tag.fieldno), wire_str (tag.wire), varint, (int) varint, (char *) buf + bytes);
            bytes += (int) varint;
        }
    }

    //printf ("consumed %d bytes (out of %d)\n", bytes, len);

    pb_istream_t stream = pb_istream_from_buffer ((uint8_t *) buf, rlen);
    int ret = pb_decode (&stream, extensions_api_cast_channel_CastMessage_fields, &rmsg);

    //printf ("decode ok=%d\n", ret);
    if (ret)
    {
//        printf ("version        : %d\n", rmsg.protocol_version);
//        printf ("source-id      : %s\n", (char *) rmsg.source_id.arg);
//        printf ("destination-id : %s\n", (char *) rmsg.destination_id.arg);
//        printf ("namespace      : %s\n", (char *) rmsg.namespace.arg);
//        printf ("payload-utf8   : %s\n", (char *) rmsg.payload_utf8.arg);

        bool ok;

        /* We've received valid messages from the chromecast so we're now
         * officially connected */
        if (app.state == STATE_CONNECTING)
        {
            send_msg (ssl, receiver_ns, get_status_msg);
            send_msg (ssl, receiver_ns, get_app_availability_msg);
            app.state = STATE_CONNECTED;
        }

        event (EVENT_CONNECTED, NULL);

        if (strstr (rmsg.payload_utf8.arg, "PING"))
        {
            printf ("tls: <- PING\n");
            enqueue (TLS_SEND_PONG, 0);
#if 0
            ok = send_msg (ssl, send_buf, sizeof (send_buf), heartbeat_ns, pong_msg);
            if (ok)
            {
                printf ("> PONG\n");

                if (0)
                    http_event_send ("Connected");
            }
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_status_msg);
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, get_app_availability_msg);
            if (0)
                send_msg (ssl, send_buf, sizeof (send_buf), receiver_ns, launch_msg);
#endif
        }
        else if (strstr (rmsg.payload_utf8.arg, "PONG"))
        {
            printf ("tls: <- P0NG\n");
            enqueue (TLS_SEND_PING, 5000);

        }
        else if (strstr (rmsg.namespace.arg, "receiver"))
        {
            json_t pool[128];
            const json_t *data;

            printf ("Parsing JSON\n");

#define JSON_INT(DATA, KEY, J) (((J = json_getProperty (DATA, KEY)) && json_getType (J) == JSON_INTEGER) ? json_getInteger (J) : -1) 
#define JSON_STR(DATA, KEY, J) (((J = json_getProperty (DATA, KEY)) && json_getType (J) == JSON_TEXT) ? json_getValue (J) : NULL) 
#define JSON_OBJ(DATA, KEY, J) (((J = json_getProperty (DATA, KEY)) && json_getType (J) == JSON_OBJ) ? json_getValue (J) : NULL) 
            
            data = json_create (rmsg.payload_utf8.arg, pool, sizeof (pool));
            if (data)
            {
                json_dump (data, 0);
            }
            else
            {
                printf ("Failed to parse json\n");
            }
        }
    }
    else
    {
        printf ("Failed to decode message: %s\n", PB_GET_ERROR (&stream));
    }

    free (rmsg.source_id.arg);
    free (rmsg.destination_id.arg);
    free (rmsg.namespace.arg);
    free (rmsg.payload_utf8.arg);
}


static void
tls_read (SSL *ssl)
{
    size_t rd;
    u8 recv_buf[1024] = {};

    if (!ssl)
    {
        printf ("Invalid SSL object\n");
        return;
    }

    if (SSL_read_ex (ssl, recv_buf, sizeof (recv_buf), &rd))
    {
#if 0
        hex_dump (recv_buf, rd);
#endif

        parse_recv_msg (recv_buf, rd, ssl);
    }

    if (SSL_get_error (ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        OPENSSL_DUMP_ERR ();
    }
}



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
            send_msg (app.ssl, heartbeat_ns, ping_msg);
            printf ("tls: -> PING\n");
            break;
        case TLS_SEND_PONG:
            send_msg (app.ssl, heartbeat_ns, pong_msg);
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

    app.web.port = 5001;
    app.web.clients = &app.pfds[WEB_CLIENT_FD_START];
    if (!http_listen_socket_setup (&app.web))
    {
        printf ("Failed to setup HTTP socket\n");
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

        int shortest_timeout = 20000;
        long now = time_ms ();

        printf ("queue: check pending msgs\n");

        for (int i = 0; i < ARRAY_LEN (app.queue); i++)
        {
            struct delayed_msg *msg = &app.queue[i];

            if (msg->pending)
            {
                long time_waited = now - msg->started_at;
                long remaining = msg->delay - time_waited;

                printf ("queue: msg %s has waited %ld/%ld ms\n", msg_str (msg), time_waited, msg->delay);

                if (remaining <= 0)
                {
                    do_send (msg);
                }
                else if (remaining > 0 && remaining < shortest_timeout)
                {
                    shortest_timeout = remaining;

                    printf ("queue: new shortest timeout: %ld ms\n", shortest_timeout);
                }
            }
        }

        timeout = shortest_timeout;

        printf ("poll: nfds=%d timeout=%ld\n", app_nfds (), timeout);
        int ret = poll (app.pfds, app_nfds (), timeout);

        for (int i = 0; ret > 0 && i < app_nfds (); i++)
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
                    printf ("http: read fd[%d]=%d\n", i, app.pfds[i].fd);
                    if (http_read (&app.web, app.pfds[i].fd) <= 0)
                    {
                        printf ("http-client(%d) closed\n", app.pfds[i].fd);

                        close (app.pfds[i].fd);

                        // TODO: might need to keep the valid pfds contiguous
                        app.pfds[i].fd = -1;
                        app.pfds[i].events = 0;
                        app.web.client_count--;

                        app.web.streaming &= ~(1 << i);
                        printf ("http-streaming: 0b%b\n", app.web.streaming);
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
